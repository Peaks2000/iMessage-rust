# Apple device provisioning

The Linux engine can use an already registered Apple device session. It also has an experimental legacy IDS registration command for a device that already has a push session, Apple authentication credentials, and fresh device validation data. The required credentials must be available from an Apple device and account you control. Extracting keys, generating validation data, and signing in to set up the initial Apple session require external provisioning today.

Use a private directory and set the input plist to mode `0600`. Both commands accept binary or XML property lists. Use plist `data` values for bytes, including certificates and private keys encoded in DER. In an XML plist, a `data` value holds base64.

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
