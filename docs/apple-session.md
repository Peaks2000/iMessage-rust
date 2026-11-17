# Apple iMessage sessions

The Linux desktop opens a saved iMessage registration from Linux Secret Service and connects directly to Apple. First-time device registration using Linux alone is unavailable. Apple Account authentication and SMS verification alone do not provide the push identity and device validation needed by Apple's iMessage registration service.

Open **Settings → This Computer → Import Registered Session** if you already have a compatible registered session. Linux Secret Service stores the session for future launches. The command-line tools below are available for already provisioned devices.

Use a private directory and give only your user access to any imported plist. Setup accepts binary and XML property lists. Use plist `data` values for certificates and private keys.

## Optional Mac-assisted setup

On the Mac, enable **Remote Login** for your user. In the Linux app, open **Settings → This Computer → Set Up with a Mac**. You can also right-click the **iMessage** launcher or run `imessage --mac-setup`.

Enter the Mac SSH address, Mac login password, Apple Account and Apple Account password. Leave the Mac password blank if you use SSH keys. The app keeps the Mac password in memory during setup and copies its bundled helper to `~/.local/bin/imessage-mac-device` after SSH sign-in. On the first SSH connection, compare the fingerprint with the matching public host key in `/etc/ssh` on the Mac.

The helper can use the system push signers from Apple's OS X El Capitan 10.11.6 Combo Update and macOS Big Sur 11.7.10. On El Capitan, it also uses the Combo Update's validation routines. The helper checks the exact system binaries before calling those routines. On Big Sur and later, it uses the validation interface in AppleAccount.framework. If the native push signer is unavailable and there is no cached push identity, setup needs your authorised Apple-issued activation chain (`activation-chain.pem`) and matching owner-only RSA private key (`activation-key.pem`) in `~/Library/Application Support/LinuxMessages`. Apple validates the signed activation before issuing a push certificate.

To rebuild the bundled universal helper from source on Linux, run `bash tools/build-macos-device-helper.sh /path/to/MacOSX10.11.sdk /path/to/MacOSX11.3.sdk` with Clang, ld64.lld and llvm-lipo installed.

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
