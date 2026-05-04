# Architecture

Two-page tour of the runtime structure for anyone (human or AI) who wants
to change the client without breaking it.

## Tasks at runtime

```
              ┌────────────────────┐
              │   run(config, rx)  │   one task
              └──────┬─────────────┘
                     │ for each ServiceConfig
                     ▼
              ┌────────────────────┐
              │   run_service      │   one task per service
              │   (reconnect loop) │
              └──────┬─────────────┘
                     │
                     ▼
              ┌────────────────────┐
              │ run_control_channel│   one task per *live* control conn
              │  (handshake +      │
              │   command loop)    │
              └──────┬─────────────┘
                     │ on CreateDataChannel
                     ▼
              ┌────────────────────┐
              │ run_data_channel   │   one task per visitor connection
              │  (handshake +      │
              │   SOCKS5 + bridge) │
              └────────────────────┘
```

- `run` is the top-level entry. It spawns one supervisor task per service
  and parks on the shutdown channel. When shutdown fires, supervisors are
  aborted; in-flight data channels are dropped along with them.

- `run_service` owns the reconnect loop. On any error it sleeps
  `retry_interval` seconds (clamped to ≥1) and tries again. If the
  control channel ran for more than 3 seconds before failing, the failure
  is logged at `warn`; otherwise at `error` (early failure usually means
  config / auth, not network).

- `run_control_channel` does the rathole handshake on a fresh TCP
  connection, then enters the command loop. Each iteration reads exactly
  one `ControlChannelCmd` (4 bytes) with a `heartbeat_timeout`-scoped
  `tokio::select!` so we can detect server silence without a separate
  task.

- `run_data_channel` is spawned per `CreateDataChannel`. It opens a new
  TCP connection, sends the data Hello (using the session key as the
  digest), expects `StartForwardTcp`, then hands over to `socks5::accept`
  and `copy_bidirectional`.

## Why not multiplex over the control channel?

Rathole's design uses one TCP connection per visitor (the data channel)
plus one shared control TCP. We follow the same pattern because it is
what the upstream server expects — the server explicitly waits for a new
TCP connection after sending `CreateDataChannel`.

## Shutdown semantics

We rely on two things:

1. `shutdown` is a `broadcast::Receiver<bool>` shared by every supervisor
   task. Sending on the matching sender (or dropping it) wakes them all.
2. Data channel tasks are not shutdown-aware. They are torn down by
   aborting their parents (the supervisor) — the dropped `TcpStream`
   surfaces as an `Err` in the bidirectional copy and the task exits.

This is intentionally simple. Graceful drain (let in-flight visitors
finish before exit) is **not** implemented. If you add it, do it via an
explicit "stop accepting new" flag, not via the shutdown broadcast.

## Error policy

- I/O errors → bubble up as `Error::Io`, which causes the control task to
  drop and the supervisor to reconnect.
- SOCKS5 parse errors → log at `debug`, close the data channel. They do
  not affect the control channel.
- Auth / service-not-exist → log at `error`, retry forever. Operator
  should fix config; we do not give up because the server may simply not
  be configured yet.
- Heartbeat timeout → return `Error::HeartbeatTimeout`, supervisor
  reconnects with the normal retry interval.

## Dependency budget

Runtime (released binary):

| Crate              | Why                                |
|--------------------|------------------------------------|
| `tokio`            | runtime — required by the user     |
| `sha2`             | session key + service digest       |
| `tracing`          | structured logs (no subscriber)    |
| `clap`             | only with `cli` feature            |
| `tracing-subscriber` | only with `cli` feature; `fmt` feature only — no regex-based `env-filter` |

Library users who turn off `default-features` get **3 dependencies**
(`tokio`, `sha2`, `tracing`).

### Log level

The CLI binary reads `RUST_LOG` as a plain level name (`error`, `warn`,
`info`, `debug`, `trace`, `off`). Module-level directives
(`RUST_LOG=mymodule=debug`) are intentionally not supported — they would
require pulling in `regex-automata` (~130 KiB of binary).

Dev / test:

- `rathole` (git dev-dep, pinned rev) — the real upstream server, used by
  the integration test exactly as upstream tests use it.
- `tokio` (full), `tracing-subscriber`, `anyhow`, `rand` — test ergonomics.
