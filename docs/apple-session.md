# Apple device provisioning

The Linux engine can sign in to an Apple Account with SMS verification and register a legacy iMessage device. You can also import a previously registered session or register a device using an existing Apple authentication certificate. The on-device desktop flow provisions Anisette and requests APNs activation from Linux, using a prepared profile to supply the Apple validation proofs and activation credentials.

Use a private directory and give only your user access to the input plist. On Linux, you can set this in your file manager under **Properties → Permissions** or use mode `0600`. Setup accepts binary and XML property lists. Use plist `data` values for bytes, including certificates and private keys encoded in DER. In an XML plist, a `data` value holds base64.

## Set up in the desktop app

Open **Settings** with **Ctrl+,** or from the conversation details button. Under **This Computer**, choose one of these options.

- **Set Up Apple Account** opens [on-device setup](#on-device-setup). **Device Options** also offers [a Mac helper](#automatic-device-setup) and the original [device plist](#sign-in-to-an-apple-account-with-sms) workflow.
- **Import Session** opens an existing registered session plist. The session format is described below.

Both options save the session in Linux Secret Service and switch the app to **This Computer**. Browse uses Zenity on Linux when it is available. You can enter file paths directly. The desktop keeps the password and SMS code in memory during sign-in.

## On-device setup

Linux generates Anisette headers locally, handles the Apple Account password and SMS code, and performs Apple push activation and iMessage registration. This path uses native ADI cryptographic code from [apple-auth](https://github.com/apple-auth/apple-auth/tree/98c862f7bebc8283a9b87f1578e703f0765dc81d). The profile still needs two separate, fresh Apple validation proofs issued for its device identity. Prepare the profile shortly before signing in. Apple decides whether to accept the proofs and activate the identity.

### Build the local Anisette library

Install CMake, a C++20 compiler and the development headers for Mbed TLS. Then run the build script on Linux.

```sh
tools/build-local-adi.sh "$HOME/.local/lib/linux-imessage"
```

The Rust app looks for the library at that path. An installation with a different library path can set `IMESSAGE_ANISETTE_LIBRARY`.

### Prepare the profile and sign in

If you have access to an authorised Mac, configure the activation material and build the [macOS helper](#set-up-the-helper-on-macos). Run this command locally on that Mac.

```sh
"$HOME/.local/bin/imessage-mac-device" export-local "$HOME/local-device.plist"
```

Transfer the profile privately and open **Settings → This Computer → Set Up Apple Account** on Linux. Choose the profile, enter your Apple Account and password, then select **Sign In**. To prefill the path, put the file in the Linux app's data directory as `local-device.plist` or set `IMESSAGE_LOCAL_DEVICE`. The file needs mode `0600`. It contains private activation credentials, so keep it private and remove the transferred copy after sign-in. Your registered session and ADI identity are saved in Linux Secret Service.

A profile from another authorised provider can use this format.

| Key | Value |
| --- | --- |
| `version` | Integer `1` |
| `computer` | The same six values returned by `describe` below, including the UUID as a string |
| `qualification-data` | Fresh Apple device validation proof as plist data for account authorization |
| `registration-data` | A separate fresh Apple device validation proof as plist data for iMessage registration |
| `activation` | Dictionary with the PEM certificate `chain` and matching DER RSA signing `key`, both plist data |
| `push` | Alternative to `activation`. Dictionary with matching DER push `certificate` and RSA `key` as plist data, and an optional 32-byte push `token` |

## Automatic device setup

Use a Mac or a booted Hackintosh you control. The helper uses its actual macOS hardware identity and private system frameworks to get fresh validation data. A Mac with OpenCore uses the identity supplied by its boot configuration. The helper also needs an Apple-issued FairPlay activation certificate chain and its matching private RSA key that you are authorised to use. The supplied helper expects an unencrypted PEM key in an owner-only file, since it runs over SSH without a terminal. Apple checks the signature and decides whether to issue a push certificate.

### Set up the helper on macOS

With the Xcode command-line tools installed, build the helper from this repository on the Mac.

```sh
install -d -m 700 "$HOME/.local/bin" "$HOME/Library/Application Support/LinuxMessages"
xcrun clang -fobjc-arc -framework Foundation tools/macos-device-helper.m \
  -o "$HOME/.local/bin/imessage-mac-device"
```

Put your activation chain and signing key in the paths below.

| File | Contents |
| --- | --- |
| `~/Library/Application Support/LinuxMessages/activation-chain.pem` | Apple FairPlay activation certificate chain in PEM format |
| `~/Library/Application Support/LinuxMessages/activation-key.pem` | Matching RSA signing key in PEM format, accessible only to your user |

Enable SSH access on the Mac. From Linux, verify its SSH host key and configure key-based login as the macOS user who can access the helper and signing key. The app uses your normal SSH configuration and known hosts. Check that the helper is reachable with `ssh user@mac.local '~/.local/bin/imessage-mac-device describe'`. The command prints the Mac's hardware identifiers.

### Sign in from Linux

1. Open **Settings → This Computer → Set Up Apple Account → Device Options → Use a Mac helper** and enter the Mac's SSH address or your SSH alias.
2. Enter your Apple Account and password. If your iMessage address differs from the account name, enter it under **Device Options**.
3. Select **Sign In**. Choose a trusted phone number and enter Apple's SMS code if prompted.

Linux generates its own push private key, requests a signed push certificate, obtains an APNs token, and saves the push identity to Secret Service for retries. The helper supplies fresh Anisette and hardware validation while Linux completes Apple sign-in and legacy iMessage registration. Apple Account credentials and SMS codes go directly to Apple. The Mac helper handles device validation and activation signing. The Linux app handles messages.

Under **Device Options**, you can select an OpenCore `config.plist` to check that its model, serial number, and UUID match the Mac helper. Use the config for the Hackintosh you are actually running.

### Use a local helper

The built-in SSH connection is optional. Under **Device Options**, select a trusted local executable, or configure it with `IMESSAGE_DEVICE_HELPER`. The app also discovers an executable named `device-helper` in its data directory. The executable accepts one operation argument and writes the result to stdout.

| Operation | Input and result |
| --- | --- |
| `describe` | JSON strings named `model`, `serial`, `uuid`, `os-version`, `build-version`, and `device-name` |
| `activation-sign` | Reads the Apple activation plist on stdin. Returns JSON strings `certificate-chain` and `signature`, each base64 encoded |
| `anisette` | Returns fresh provider headers as a JSON object of strings, using the [header contract below](#anisette-helper-contract) |
| `validation` | Returns base64-encoded validation data from a fresh Apple validation request |

The Linux activation and APNs protocol paths have offline tests. The native helper and full Apple enrollment still need a live end-to-end test on a compatible Mac with authorised signing material.

## Import a registered session

```sh
chmod 600 apple-session.plist
./target/release/messages-server import-session apple-session.plist
```

The plist is a dictionary with the following keys.

| Key | Value |
| --- | --- |
| `version` | Integer `1` |
| `handle` | Your registered Apple address, for example `mailto:me@example.com` or `tel:+441234567890` |
| `push-token` | 32-byte APNs device token |
| `push-certificate`, `push-private-key` | Matching DER X.509 certificate and RSA private key for the APNs session |
| `ids-certificate`, `ids-private-key` | Matching DER X.509 certificate and RSA private key registered for the iMessage service and the same device |
| `signing-private-key` | DER P-256 private key registered as the legacy iMessage signing identity |
| `encryption-private-key` | DER 1280-bit RSA private key registered as the legacy iMessage encryption identity |
| `protocol-version` | Integer for the provisioned Apple's device IDS protocol version |
| `user-agent` | User-agent version string from that device, without a service-specific prefix |

The CLI validates the file shape, token size, key types, and certificate/key matches. Apple checks the credentials when the engine connects and looks up a recipient.

## Sign in to an Apple Account with SMS

```sh
chmod 600 apple-device.plist
./target/release/messages-server login apple-device.plist \
  --anisette-helper /absolute/path/to/anisette-headers
```

Use the device fields from [legacy IDS registration](#request-a-legacy-ids-registration). Leave out `user-id`, `auth-certificate`, and `auth-private-key` because the command obtains them after Apple sign-in. Include the original APNs token and certificate/key pair, device metadata, and fresh `validation-data` from your validation device.

Enter your Apple Account and password in the terminal. If Apple requests a verification code, select one of the account's trusted phone numbers when given a choice. Enter the six digits from Apple's text. If Apple has already sent a code, the command uses the existing challenge. When Apple accepts the sign-in and registration, the command saves the device session through Secret Service or the supplied `--vault-key-file`. The password, SMS code, and intermediate Apple login tokens are held in memory for the sign-in. [Apple's guide to receiving verification codes](https://support.apple.com/102606)

### Anisette helper contract

Supply a trusted local executable that calls your provisioned Anisette provider. The command runs it without arguments or input and reads a single JSON object of string-valued headers from stdout. The helper supplies device authentication data and receives no account details or SMS codes. It must return fresh time and one-time password values and use the same provisioned device identity across calls.

| Required JSON key | Provider value |
| --- | --- |
| `X-Apple-I-MD` | Fresh device one-time password |
| `X-Apple-I-MD-M` | Provisioned machine identifier |
| `X-Apple-I-MD-RINFO` | Routing info as a decimal string |
| `X-Apple-I-MD-LU` | Stable local user identifier |
| `X-Mme-Device-Id` | Stable device UUID |
| `X-Apple-I-Client-Time` | Current UTC timestamp in ISO 8601 format |
| `X-Mme-Client-Info`, `User-Agent` | Values matching the provider's device platform |

The command also accepts `X-Apple-I-SRL-NO`, `X-Apple-I-TimeZone`, `X-Apple-Locale`, `X-Apple-I-ROM`, and `X-Apple-I-MLB`. Anisette generation remains with the operator's provider. [Anisette v3 provider](https://github.com/Dadoum/anisette-v3-server) · [GrandSlam SMS protocol reference](https://github.com/OpenBubbles/apple-private-apis/blob/b8598d2c1656ae73fbe0f1be1b18222ea7cadb0a/icloud-auth/src/client.rs)

## Request a legacy IDS registration

This sends the validation data to Apple, registers newly generated legacy text-message keys, and saves the returned session. Use a dedicated push identity that you intend to register for this application. A current Apple service may refuse the legacy capability set.

```sh
chmod 600 apple-registration.plist
./target/release/messages-server register-session apple-registration.plist
```

Include `version`, `handle`, `push-token`, `push-certificate`, `push-private-key`, `protocol-version`, and `user-agent` as above. Add these values.

| Key | Value |
| --- | --- |
| `user-id` | Apple IDS authentication user identifier for the account |
| `auth-certificate`, `auth-private-key` | Matching DER X.509 certificate and RSA private key from Apple's account authentication step |
| `device-name`, `hardware-version`, `os-version`, `software-version` | Strings from the same validation device |
| `private-device-data` | Apple's private device metadata dictionary for the validation device |
| `validation-data` | Fresh Apple hardware validation bytes |

## Use an encrypted vault on a headless server

Generate a random key file in a directory accessible only to the server account. Store it separately from the service's data directory and supply the same file on import or registration and at startup.

```sh
install -d -m 700 ./server-secrets
(umask 077 && openssl rand -out ./server-secrets/vault.key 32)
./target/release/messages-server --data-dir ./server-data import-session apple-session.plist \
  --vault-key-file ./server-secrets/vault.key
./target/release/messages-server --data-dir ./server-data serve \
  --vault-key-file ./server-secrets/vault.key
```

The final command binds to loopback by default. For a network server, use the TLS and login options in the [README](../README.md).
