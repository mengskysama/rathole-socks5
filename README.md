# rathole-socks5

A minimal Rust client for [rathole](https://github.com/rathole-org/rathole)
that replaces the official client's fixed `local_addr` forwarder with an
embedded **SOCKS5 server** — library-friendly and tiny.

```
SOCKS5 client  ──►  rathole server (public port)
                          ▲
                          │ rathole control + data channels (TCP)
                          ▼
                   rathole-socks5 (this crate)  ──►  arbitrary TCP target
```

## Highlights

- **Tiny.** TCP transport only. No TLS, no Noise, no WebSocket, no TOML,
  no hot-reload. Three runtime crates (`tokio`, `sha2`, `tracing`) when
  used as a library.
- **Library-first.** `pub fn run(config, shutdown)`; embed it in your
  own tokio app.
- **CLI when you want it.** `cargo install` gives you a single binary
  configured by flags.

## CLI usage

With SOCKS5 authentication:

```bash
rathole-socks5 \
  --remote-addr rathole.example.com:2333 \
  --service my_socks \
  --token shared-secret-token \
  --socks5-username test_user \
  --socks5-password your_password
```

| Flag                  | Required | Default | Meaning                                   |
|-----------------------|:--------:|:-------:|-------------------------------------------|
| `--remote-addr`       |    ✓     |   —     | rathole server control listener (`host:port`) |
| `--service`           |    ✓     |   —     | service name; must match the server config |
| `--token`             |    ✓     |   —     | shared-secret token for the service       |
| `--heartbeat-timeout` |          | `40`    | seconds; reconnect if no frame seen within. `0` disables. |
| `--retry-interval`    |          | `1`     | seconds between reconnection attempts     |
| `--socks5-username`   |          | —       | require SOCKS5 username/password auth; must pair with `--socks5-password` |
| `--socks5-password`   |          | —       | SOCKS5 password; must pair with `--socks5-username`       |

Use `RUST_LOG` to control log verbosity (`error`, `warn`, `info`, `debug`, `trace`, `off`):

```bash
RUST_LOG=debug rathole-socks5 --remote-addr ...
```

Once running, verify the proxy works:

```bash
# socks5h: resolve DNS on the proxy side
curl -x socks5h://test_user:your_password@server_ip:1080 http://google.com
```

> **Security warning**: the public SOCKS5 port (`bind_addr` in the rathole server config) is an open proxy for anyone who can reach it. If exposed to the internet without `--socks5-username`/`--socks5-password`, anyone can relay arbitrary traffic through your server. Always set credentials, and consider firewall rules to restrict access to trusted IPs.

### Server side

You need a stock rathole server. Minimal config:

```toml
# server.toml
[server]
bind_addr = "0.0.0.0:2333"
default_token = "shared-secret-token"

[server.transport]
type = "tcp"

[server.services.my_socks]
bind_addr = "0.0.0.0:1080"   # the public SOCKS5 port
```

```bash
rathole --server server.toml
```

Now any SOCKS5 client pointed at `your-server-host:1080` will tunnel
through to the targets resolved on the rathole-socks5 side.

## Library usage

```toml
# Cargo.toml
[dependencies]
rathole-socks5 = { version = "0.1", default-features = false }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync"] }
```

```rust
use rathole_socks5::ClientConfig;
use tokio::sync::broadcast;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = ClientConfig::new(
        "rathole.example.com:2333",
        "my_socks",
        "shared-secret-token",
    );

    // Wire up your own shutdown — for instance, on Ctrl-C:
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });

    rathole_socks5::run(cfg, shutdown_rx).await?;
    Ok(())
}
```

With SOCKS5 authentication:

```rust
let mut cfg = ClientConfig::new("rathole.example.com:2333", "my_socks", "token");
cfg.socks5_username = Some("alice".into());
cfg.socks5_password = Some("s3cr3t".into());
```

### Disabling the CLI from your binary build

When embedding as a library and you don't need the CLI helpers:

```toml
rathole-socks5 = { version = "0.1", default-features = false }
```

This drops `clap` and `tracing-subscriber` from the dependency graph.

## Configuration model

| Knob                | Type           | Notes                                  |
|---------------------|----------------|----------------------------------------|
| `remote_addr`       | `String`       | rathole control listener `host:port`   |
| `service_name`      | `String`       | must match `[server.services.<name>]`  |
| `token`             | `String`       | shared secret                          |
| `heartbeat_timeout` | `u64` (secs)   | `0` disables                           |
| `retry_interval`    | `u64` (secs)   | minimum `1`, no exponential backoff    |
| `socks5_username`   | `Option<String>` | set together with `socks5_password` to require auth |
| `socks5_password`   | `Option<String>` | set together with `socks5_username`    |

## Testing

```bash
# Lib + bin
cargo build

# Unit tests
cargo test --lib

# End-to-end against a real upstream rathole server
cargo test
```

The end-to-end test (`tests/integration_test.rs`) boots an in-process
upstream rathole server through the git dev-dependency on
`github.com/rathole-org/rathole` (pinned by `rev` in `Cargo.toml`), runs
`rathole-socks5` against it, and drives both serial and concurrent
SOCKS5 sessions.

## Limitations

- TCP transport only (no TLS / Noise / WebSocket).
- SOCKS5 CONNECT only (no UDP ASSOCIATE / BIND, no auth methods).

## License

MIT License
