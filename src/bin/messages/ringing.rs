use std::{collections::HashMap, future::Future, process::Stdio, time::Duration};

use anyhow::Result;
use futures_util::StreamExt;
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
const NOTIFICATIONS: &str = "org.freedesktop.Notifications";
const NOTIFICATION_PATH: &str = "/org/freedesktop/Notifications";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RingAction {
    Open,
    Answer(CallMode),
    Decline,
}

fn notification_actions(mode: Option<CallMode>, can_answer: bool) -> &'static [&'static str] {
    if !can_answer {
        &["default", "Open iMessage", "decline", "Decline"]
    } else if mode == Some(CallMode::Video) {
        &[
            "default",
            "Open iMessage",
            "answer-video",
            "Answer Video",
            "answer-audio",
            "Answer as Audio",
            "decline",
            "Decline",
        ]
    } else {
        &[
            "default",
            "Open iMessage",
            "answer-audio",
            "Answer",
            "decline",
            "Decline",
        ]
    }
}

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
    pub(super) call: (Uuid, Option<CallMode>),
    stop: watch::Sender<()>,
    task: JoinHandle<()>,
}

impl RingAlert {
    pub(super) fn start(
        call: IncomingCall,
        can_answer: bool,
        invoked: impl Fn(RingAction, Option<String>) + Send + 'static,
    ) -> Self {
        let announced = (call.id, call.mode);
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
                let _ = notify(call, cancel.clone(), use_system_sound, can_answer, invoked).await;
            };
            tokio::join!(player, notification);
        });
        Self {
            call: announced,
            stop,
            task,
        }
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

async fn notify(
    call: IncomingCall,
    cancel: watch::Receiver<()>,
    use_system_sound: bool,
    can_answer: bool,
    invoked: impl Fn(RingAction, Option<String>),
) -> Result<()> {
    let connection = timeout(DESKTOP_TIMEOUT, zbus::Connection::session()).await??;
    notify_on(
        &connection,
        call,
        cancel,
        use_system_sound,
        can_answer,
        invoked,
    )
    .await
}

async fn notify_on(
    connection: &zbus::Connection,
    call: IncomingCall,
    mut cancel: watch::Receiver<()>,
    use_system_sound: bool,
    can_answer: bool,
    invoked: impl Fn(RingAction, Option<String>),
) -> Result<()> {
    let proxy = timeout(
        DESKTOP_TIMEOUT,
        zbus::Proxy::new(connection, NOTIFICATIONS, NOTIFICATION_PATH, NOTIFICATIONS),
    )
    .await??;
    // Subscribe before posting and preserve the order of activation tokens and actions.
    let mut signals = timeout(DESKTOP_TIMEOUT, proxy.receive_all_signals()).await??;
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
    let actions = notification_actions(call.mode, can_answer);
    let response = timeout(
        DESKTOP_TIMEOUT,
        proxy.call_method(
            "Notify",
            &(
                "iMessage",
                0u32,
                "camera-video",
                format!("{title} · {caller}"),
                "",
                actions,
                hints,
                i32::try_from(remaining)?,
            ),
        ),
    )
    .await??;
    let id: u32 = response.body().deserialize()?;
    let reply_header = response.header();
    let owner = reply_header
        .sender()
        .ok_or_else(|| anyhow::anyhow!("Missing desktop notification sender"))?;
    let mut token = None;
    loop {
        let message = tokio::select! {
            biased;
            _ = cancel.changed() => break,
            () = tokio::time::sleep_until(expiry) => break,
            Some(message) = signals.next() => message,
        };
        let header = message.header();
        if header.sender() != Some(owner) {
            continue;
        }
        let body = message.body();
        match header.member().map(|member| member.as_str()) {
            Some("ActivationToken") => {
                if let Ok((target, value)) = body.deserialize::<(u32, &str)>()
                    && target == id
                    && !value.is_empty()
                    && value.len() <= 4096
                {
                    token = Some(value.to_owned());
                }
            }
            Some("ActionInvoked") => {
                let Ok((target, key)) = body.deserialize::<(u32, &str)>() else {
                    continue;
                };
                if target != id || !actions.as_chunks::<2>().0.iter().any(|pair| pair[0] == key) {
                    continue;
                }
                let action = match key {
                    "default" => RingAction::Open,
                    "answer-audio" => RingAction::Answer(CallMode::Audio),
                    "answer-video" => RingAction::Answer(CallMode::Video),
                    "decline" => RingAction::Decline,
                    _ => continue,
                };
                invoked(action, token.take());
            }
            Some("NotificationClosed")
                if body
                    .deserialize::<(u32, u32)>()
                    .is_ok_and(|(target, _)| target == id) =>
            {
                return Ok(());
            }
            _ => (),
        }
    }
    let _ = timeout(
        DESKTOP_TIMEOUT,
        connection.call_method(
            Some(owner.as_str()),
            NOTIFICATION_PATH,
            Some(NOTIFICATIONS),
            "CloseNotification",
            &(id,),
        ),
    )
    .await;
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
        Incoming {
            title: String,
            timeout_ms: i32,
            actions: Vec<String>,
        },
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
            assert_eq!(
                hints
                    .get("suppress-sound")
                    .and_then(|value| bool::try_from(value).ok()),
                Some(true)
            );
            let _ = self.0.send(DesktopEvent::Incoming {
                title: summary.to_owned(),
                timeout_ms: expire_timeout,
                actions,
            });
            71
        }

        async fn close_notification(&self, id: u32) {
            let _ = self.0.send(DesktopEvent::Closed(id));
        }

        #[zbus(signal)]
        async fn activation_token(
            context: &zbus::SignalContext<'_>,
            id: u32,
            token: &str,
        ) -> zbus::Result<()>;

        #[zbus(signal)]
        async fn action_invoked(
            context: &zbus::SignalContext<'_>,
            id: u32,
            key: &str,
        ) -> zbus::Result<()>;
    }

    #[tokio::test]
    #[ignore = "Uses dbus-daemon to verify desktop notifications on a private session bus"]
    async fn desktop_bus_routes_ring_actions_and_withdraws_the_announcement() -> Result<()> {
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
        let outsider = zbus::connection::Builder::address(address)?.build().await?;
        let path = "/org/freedesktop/Notifications";
        let interface = service
            .object_server()
            .interface::<_, NotificationDaemon>(path)
            .await?;
        let received_ms = now_ms();
        let call = IncomingCall {
            id: Uuid::new_v4(),
            caller: "mailto:caller@example.org".to_owned(),
            mode: Some(CallMode::Video),
            received_ms,
            expires_ms: received_ms + 45_000,
        };
        let (stop, cancel) = watch::channel(());
        let (invoked, mut actions_received) = mpsc::unbounded_channel();
        let desktop = async move {
            let Some(DesktopEvent::Incoming {
                title,
                timeout_ms,
                actions,
            }) = events.recv().await
            else {
                anyhow::bail!("Expected an incoming call notification");
            };
            assert_eq!(title, "FaceTime Video · caller@example.org");
            assert!((1..=45_000).contains(&timeout_ms));
            assert_eq!(
                actions,
                [
                    "default",
                    "Open iMessage",
                    "answer-video",
                    "Answer Video",
                    "answer-audio",
                    "Answer as Audio",
                    "decline",
                    "Decline"
                ]
            );
            let signals = interface.signal_context();
            NotificationDaemon::action_invoked(
                &zbus::SignalContext::new(&outsider, path)?,
                71,
                "answer-video",
            )
            .await?;
            NotificationDaemon::action_invoked(signals, 70, "decline").await?;
            NotificationDaemon::action_invoked(signals, 71, "invalid-action").await?;
            NotificationDaemon::activation_token(signals, 71, "open-token").await?;
            NotificationDaemon::activation_token(signals, 70, "unrelated-token").await?;
            NotificationDaemon::action_invoked(signals, 71, "default").await?;
            assert_eq!(
                actions_received.recv().await,
                Some((RingAction::Open, Some("open-token".into())))
            );
            NotificationDaemon::action_invoked(signals, 71, "answer-audio").await?;
            assert_eq!(
                actions_received.recv().await,
                Some((RingAction::Answer(CallMode::Audio), None))
            );
            NotificationDaemon::action_invoked(signals, 71, "decline").await?;
            assert_eq!(
                actions_received.recv().await,
                Some((RingAction::Decline, None))
            );
            drop(stop);
            assert!(matches!(
                events.recv().await,
                Some(DesktopEvent::Closed(71))
            ));
            Ok(())
        };
        timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                notify_on(&client, call, cancel, false, true, |action, token| {
                    let _ = invoked.send((action, token));
                }),
                desktop
            )
        })
        .await??;
        drop(service);
        drop(client);
        bus.kill().await?;
        Ok(())
    }
}
