# Apple device provisioning

The Linux engine can sign in to an Apple Account with SMS verification and register a legacy iMessage device. You can also import a previously registered session or register a device using an existing Apple authentication certificate. Initial APNs activation and Apple hardware validation are separate provisioning steps.

Use a private directory and give only your user access to the input plist. On Linux, you can set this in your file manager under **Properties → Permissions** or use mode `0600`. Setup accepts binary and XML property lists. Use plist `data` values for bytes, including certificates and private keys encoded in DER. In an XML plist, a `data` value holds base64.

## Set up in the desktop app

Open **Settings** with **Ctrl+,** or from the conversation details button. Under **This Computer**, choose one of these options.

- **Set Up Apple Account** asks for the device plist and trusted Anisette helper described below. Enter your Apple Account and password, choose a trusted phone number if prompted, then enter Apple's SMS code.
- **Import Session** opens an existing registered session plist. The session format is described below.

Both options save the session in Linux Secret Service and switch the app to **This Computer**. Browse uses Zenity on Linux when it is available. You can enter file paths directly in either form. The desktop keeps the password and SMS code in memory during the sign-in.

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
