use std::{collections::HashMap, future::Future, process::Stdio, time::Duration};

use anyhow::Result;
use linux_imessage::{CallMode, IncomingCall, display_address, now_ms};
use tokio::{
    process::Command,
    sync::watch,
    task::JoinHandle,
    time::{sleep, timeout},
};
use uuid::Uuid;
use zbus::zvariant::Value;

const RING_INTERVAL: Duration = Duration::from_secs(3);
const DESKTOP_TIMEOUT: Duration = Duration::from_secs(2);

/// An answer, decline, or outgoing call currently owns the desktop's call controls.
pub(super) struct RingPause {
    activity: watch::Sender<Option<Uuid>>,
    id: Uuid,
}

impl RingPause {
    pub(super) fn new(activity: &watch::Sender<Option<Uuid>>, id: Uuid) -> Result<Self> {
        let acquired = activity.send_if_modified(|current| {
            if current.is_some() {
                return false;
            }
            *current = Some(id);
            true
        });
        anyhow::ensure!(acquired, "A FaceTime call is already in progress");
        Ok(Self {
            activity: activity.clone(),
            id,
        })
    }
}

impl Drop for RingPause {
    fn drop(&mut self) {
        self.activity.send_if_modified(|current| {
            if *current != Some(self.id) {
                return false;
            }
            *current = None;
            true
        });
    }
}

pub(super) struct RingAlert {
    pub(super) id: Uuid,
    stop: watch::Sender<()>,
    task: JoinHandle<()>,
}

impl RingAlert {
    pub(super) fn start(call: IncomingCall) -> Self {
        let id = call.id;
        let (stop, cancel) = watch::channel(());
        let task = tokio::spawn(async move {
            let remaining = call.expires_ms.saturating_sub(now_ms());
            if remaining <= 0 || cancel.has_changed().is_err() {
                return;
            }
            let sound = play_ringtone();
            let use_system_sound = sound.is_none();
            let player = async {
                if let Some(sound) = sound {
                    repeat_sound(
                        cancel.clone(),
                        sound,
                        Duration::from_millis(remaining as u64),
                    )
                    .await;
                }
            };
            let notification = async {
                let _ = notify(call, cancel.clone(), use_system_sound).await;
            };
            tokio::join!(player, notification);
        });
        Self { id, stop, task }
    }

    pub(super) async fn stop(self) {
        drop(self.stop);
        let _ = self.task.await;
    }
}

fn play_ringtone() -> Option<impl Future<Output = Option<()>>> {
    let mut player = Command::new("canberra-gtk-play");
    player
        .args([
            "--id=phone-incoming-call",
            "--description=FaceTime incoming call",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let first = player.spawn().ok()?;
    Some(async move {
        // Each invocation lets the active sound theme and desktop event volume choose the sound.
        let mut child = first;
        loop {
            let status = timeout(Duration::from_secs(12), child.wait())
                .await
                .ok()?
                .ok()?;
            if !status.success() {
                return None;
            }
            sleep(RING_INTERVAL).await;
            child = player.spawn().ok()?;
        }
    })
}

async fn repeat_sound(
    mut cancel: watch::Receiver<()>,
    sound: impl Future<Output = Option<()>>,
    remaining: Duration,
) {
    tokio::select! {
        biased;
        _ = cancel.changed() => (),
        () = sleep(remaining) => (),
        _ = sound => (),
    }
}

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)] // Fields of the freedesktop Notify method.
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    fn close_notification(&self, id: u32) -> zbus::Result<()>;
}

async fn notify(
    call: IncomingCall,
    cancel: watch::Receiver<()>,
    use_system_sound: bool,
) -> Result<()> {
    let connection = timeout(DESKTOP_TIMEOUT, zbus::Connection::session()).await??;
    notify_on(&connection, call, cancel, use_system_sound).await
}

async fn notify_on(
    connection: &zbus::Connection,
    call: IncomingCall,
    mut cancel: watch::Receiver<()>,
    use_system_sound: bool,
) -> Result<()> {
    let proxy = timeout(DESKTOP_TIMEOUT, NotificationsProxy::new(connection)).await??;
    let remaining = call.expires_ms.saturating_sub(now_ms());
    if remaining <= 0 || cancel.has_changed().is_err() {
        return Ok(());
    }
    let expiry = tokio::time::Instant::now() + Duration::from_millis(remaining as u64);
    let title = match call.mode {
        Some(CallMode::Video) => "FaceTime Video",
        Some(CallMode::Audio) => "FaceTime Audio",
        None => "FaceTime",
    };
    let mut hints = HashMap::from([
        ("category", Value::from("call.incoming")),
        (
            "desktop-entry",
            Value::from("io.github.Peaks2000.LinuxMessages"),
        ),
        ("transient", Value::from(true)),
    ]);
    if use_system_sound {
        hints.insert("sound-name", Value::from("phone-incoming-call"));
    } else {
        hints.insert("suppress-sound", Value::from(true));
    }
    let caller = display_address(&call.caller);
    let id = timeout(
        DESKTOP_TIMEOUT,
        proxy.notify(
            "iMessage",
            0,
            "camera-video",
            &format!("{title} · {caller}"),
            "",
            &[],
            hints,
            i32::try_from(remaining)?,
        ),
    )
    .await??;
    tokio::select! {
        biased;
        _ = cancel.changed() => (),
        () = tokio::time::sleep_until(expiry) => (),
    }
    let _ = timeout(DESKTOP_TIMEOUT, proxy.close_notification(id)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncBufReadExt, BufReader},
        sync::{mpsc, oneshot},
    };

    #[tokio::test]
    async fn ending_the_ring_drops_the_active_sound_task() -> Result<()> {
        let (stop, cancel) = watch::channel(());
        let (started, playing) = oneshot::channel();
        let (finished, finished_playing) = oneshot::channel::<()>();
        let sound = async move {
            let _held_by_player = finished;
            let _ = started.send(());
            std::future::pending::<Option<()>>().await
        };
        let alert = tokio::spawn(repeat_sound(cancel, sound, Duration::from_secs(45)));
        playing.await?;
        drop(stop);
        timeout(Duration::from_millis(300), alert).await??;
        assert!(finished_playing.await.is_err());
        Ok(())
    }

    enum DesktopEvent {
        Incoming { title: String, timeout_ms: i32 },
        Closed(u32),
    }

    struct NotificationDaemon(mpsc::UnboundedSender<DesktopEvent>);

    #[zbus::interface(name = "org.freedesktop.Notifications")]
    impl NotificationDaemon {
        #[allow(clippy::too_many_arguments)] // Fields of the freedesktop Notify method.
        async fn notify(
            &self,
            _app_name: &str,
            _replaces_id: u32,
            _app_icon: &str,
            summary: &str,
            _body: &str,
            actions: Vec<String>,
            hints: HashMap<String, zbus::zvariant::OwnedValue>,
            expire_timeout: i32,
        ) -> u32 {
            assert!(actions.is_empty());
            assert_eq!(
                hints
                    .get("suppress-sound")
                    .and_then(|value| bool::try_from(value).ok()),
                Some(true)
            );
            let _ = self.0.send(DesktopEvent::Incoming {
                title: summary.to_owned(),
                timeout_ms: expire_timeout,
            });
            71
        }

        async fn close_notification(&self, id: u32) {
            let _ = self.0.send(DesktopEvent::Closed(id));
        }
    }

    #[tokio::test]
    #[ignore = "Uses dbus-daemon to verify desktop notifications on a private session bus"]
    async fn ringing_posts_and_withdraws_the_announcement_on_the_desktop_bus() -> Result<()> {
        let mut bus = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut address = String::new();
        timeout(
            DESKTOP_TIMEOUT,
            BufReader::new(bus.stdout.take().unwrap()).read_line(&mut address),
        )
        .await??;
        let address = address.trim();
        let (send, mut events) = mpsc::unbounded_channel();
        let service = zbus::connection::Builder::address(address)?
            .name("org.freedesktop.Notifications")?
            .serve_at("/org/freedesktop/Notifications", NotificationDaemon(send))?
            .build()
            .await?;
        let client = zbus::connection::Builder::address(address)?.build().await?;
        let received_ms = now_ms();
        let call = IncomingCall {
            id: Uuid::new_v4(),
            caller: "mailto:caller@example.org".to_owned(),
            mode: Some(CallMode::Video),
            received_ms,
            expires_ms: received_ms + 45_000,
        };
        let (stop, cancel) = watch::channel(());
        let desktop = async move {
            let Some(DesktopEvent::Incoming { title, timeout_ms }) = events.recv().await else {
                anyhow::bail!("Expected an incoming call notification");
            };
            assert_eq!(title, "FaceTime Video · caller@example.org");
            assert!((1..=45_000).contains(&timeout_ms));
            drop(stop);
            assert!(matches!(
                events.recv().await,
                Some(DesktopEvent::Closed(71))
            ));
            Ok(())
        };
        timeout(Duration::from_secs(5), async {
            tokio::try_join!(notify_on(&client, call, cancel, false), desktop)
        })
        .await??;
        drop(service);
        drop(client);
        bus.kill().await?;
        Ok(())
    }
}
