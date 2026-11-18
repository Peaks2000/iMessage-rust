# Messages for Linux

A desktop app for Linux modelled on macOS Sequoia Messages, an optional self-hosted server, and an experimental Rust engine that talks directly to Apple's APNs and Identity Service (IDS). The desktop app can run the engine on the same computer or connect to the Rust server.

![Messages for Linux with pinned conversations, an inline photo, and a clickable link](docs/desktop.png)

## Try the desktop app

Build on Linux with Rust 1.88 or newer, C and C++ compilers, pkg-config, and the OpenSSL development headers. The desktop uses OpenGL on Wayland or X11. A desktop Secret Service provider, such as GNOME Keyring or KWallet with its Secret Service integration enabled, is required for desktop credential storage.

```sh
cargo build --locked --release
./target/release/messages
```

Use the compose icon or **Ctrl+N** to start a conversation. Enter sends and Shift+Enter adds a line break. Open **Settings** with **Ctrl+,** or from the conversation’s details button. Right-click a conversation to pin, unpin, or delete it. Deletion removes its history and attachments from the local profile or the connected server.

Right-click a text bubble or attachment to add a Tapback. Click your reaction badge to change it or select the same reaction to remove it. Received Tapbacks appear on the bubble they react to.

Use **Ctrl+V** in the message field to attach a copied image or screenshot. You can also drop a file on the conversation or use the **+** next to the composer to choose **Photos** or **Files**. The file picker uses Zenity. Photos render inline and open in a larger viewer where you can save the original. The app previews JPEG, PNG, HEIC, WebP, GIF, BMP, ICO, and TIFF images. Click a web link to open it in your default browser.

The Sequoia layout includes animated conversation selection, message arrival, the composer’s send button, and settings sheets. Translucency uses the Linux compositor. [Apple’s Sequoia Messages guide](https://support.apple.com/guide/messages/welcome/14.0/mac/15.0)

## Connect to iMessage

The desktop opens a registered iMessage session from Linux Secret Service and connects directly to Apple. For first-time registration, use **Settings → This Computer → Set Up with a Mac**. You can also restore a compatible registration using **Import Registered Session**. [Setup and session format](docs/apple-session.md)

The engine supports one-to-one text and attachments with devices that accept the legacy iMessage format. A message can contain up to eight attachments and 32 MiB of attachment data. **Sent** indicates that Apple’s courier accepted the send.

With a local Apple session registered for FaceTime, open the camera menu beside a conversation to place a **FaceTime Audio** or **FaceTime Video** call. You can answer or decline an incoming call from the app or from a desktop notification that supports actions. For a video ring, choose **Answer Video** or **Answer as Audio**. If `canberra-gtk-play` is available, iMessage repeats the desktop sound theme's incoming-call tone until you respond or the call ends. **Mute** releases the microphone, and **Camera Off** stops camera capture. Move the pointer over the video to show the call controls. You can drag your mirrored camera preview within the video call. FaceTime audio uses the PulseAudio-compatible `parec` and `pacat` tools. Video uses FFmpeg with `libx265` and prefers hardware V4L2 cameras. If capture fails, you can keep talking and choose **Retry Camera**.

With FaceTime enabled, closing the window minimizes iMessage so it can continue receiving calls. Answering or declining on another device signed in to the same FaceTime address dismisses the pending Linux ring. Press **Ctrl+Q** or right-click **Close Window** and choose **Quit iMessage** to exit.

## Sync iCloud Contacts

The Linux desktop uses the Apple Account from local iMessage setup to authorize iCloud Contacts. If you already signed in with an older build or imported a session, open **Settings → iCloud Contacts → Authorize Contacts…** once. You can also connect Contacts with an [app-specific password from Apple](https://support.apple.com/en-us/102654) when you use Server mode without a local Apple session.

The app stores the Contacts credential and any remembered Apple Account password in Linux Secret Service. It syncs directly from iCloud at launch and every 30 minutes while open. **Sync Contacts** refreshes immediately. **Disconnect** removes Contacts access and the private local cache. Synced names appear in conversations and as recipient suggestions.

## Run the optional server

Build just the server for a headless machine.

```sh
cargo build --locked --release --no-default-features --bin messages-server
./target/release/messages-server --data-dir ./server-data import-session /path/to/apple-session.plist
./target/release/messages-server --data-dir ./server-data serve
```

In the desktop app, choose **Settings → Server** and enter `http://127.0.0.1:7848`. Leave the login fields blank for this loopback configuration. Only one process can open a given local profile. If the server owns the profile, connect the desktop through **Server** mode.

For a network listener, supply a TLS certificate and key and require a username and password. The certificate must match the hostname and chain to a CA trusted by the Linux desktop.

```sh
./target/release/messages-server --data-dir ./server-data set-password --username finn
./target/release/messages-server --data-dir ./server-data serve \
  --bind 0.0.0.0:7848 --require-login \
  --tls-cert /path/to/fullchain.pem --tls-key /path/to/server.key
```

In **Settings → Server**, enter the HTTPS origin and the same username and password. **Remember password** saves the password to Linux Secret Service. The server stores a salted Argon2id password hash and accepts one account with access to the entire profile. HTTP access is limited to loopback. The server can also require the login on loopback by using `--require-login`.

## Storage and verification

The Apple session is stored in Linux Secret Service or in an AES-256-GCM vault with a separate 32-byte key on a headless server. The desktop settings file contains the connection mode, server URL, and username. Decrypted conversation history is stored in SQLite under the private data directory. A server operator with access to that directory or the running server can read the history.

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

The repository contains the Rust engine source. Protocol references are [Apple Platform Security](https://support.apple.com/guide/security/how-imessage-sends-and-receives-messages-sec70e68c949/web), [NowSecure's APNs research](https://www.nowsecure.com/blog/2021/01/27/reverse-engineering-imessage-leveraging-the-hardware-to-protect-the-software/), and [the RustPush protocol implementation](https://github.com/OpenBubbles/rustpush/tree/b3c96c23e1aae78d1229ebaccb12027624f1eaff). The bundled public roots are supplied by [Apple's Certificate Authority](https://www.apple.com/certificateauthority/). [Inter is distributed under the SIL Open Font License](assets/Inter-OFL.txt). The desktop build includes the [Fraunhofer FDK AAC codec](https://docs.rs/crate/fdk-aac-sys/0.5.0/source/aac/NOTICE).
