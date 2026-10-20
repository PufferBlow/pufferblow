# Commands and events: how the realtime layer is built

This page explains the code behind the [command/event protocol](../protocol/v1.md): what each layer does,
what it may and may not know about, and the path one command takes from a socket frame to the other
clients' screens. Read the protocol spec first for the wire format; this page is for people changing the server.

```
 websocket frame
       |
       v
 routes/ws_protocol.py        the only code that touches the socket
       |  text
       v
 commands/dispatcher.py       parse, validate, rate-limit, re-check credentials, deduplicate
       |  typed payload + ConnectionContext
       v
 commands/handlers.py         translate a payload into a service call
       |
       v
 services/messages.py         rules, authorization, persistence (no transport, no sockets)
   |-- principals/authorizer.py   who may do this?
   `-- database layer             commit
       |  ServiceResult(value, [DomainEvent...])
       v
 events/publisher.py          number the events, turn them into frames
       |
       v
 websocket/websocket_manager.py   deliver to the sessions that may see them
```

The rule that holds the design together: **each layer only knows the one beneath it.** Nothing below the socket
module imports FastAPI, and nothing above the services knows how events travel.

## The layers

### Protocol (`api/protocol/`)

Pydantic models for everything on the wire: the envelopes (`command`, `ack`, `error`, `event`, `hello`),
one model per command payload (`commands.py`), the event names (`events.py`) and the stable error codes
(`envelopes.py`, `errors.py`). The JSON Schema in `docs/protocol/v1/schema.json` is generated from these models
(`scripts/export/export_protocol_schema.py`) and a test fails when the file is stale. Payload models reject unknown
fields, so a client cannot smuggle an identity or a flag the server does not know.

### Connection session (`routes/ws_protocol.py`)

Accepts the socket, applies the connection limits, resolves the token to a `Principal`, builds the
`ConnectionContext` and then loops: read a frame, hand it to the dispatcher, send the reply, publish the events the
command produced. It also answers `ping` (which doubles as a credential re-check) and the presence frames. It is the
only place that sees a `WebSocket`. The token may arrive as an `Authorization` header or as a `bearer.<token>`
subprotocol; `core/header_auth.py` turns either into the `auth_token` parameter before this code runs.

A `ConnectionContext` holds the caller's `Principal`, the session id, the channels the session is subscribed to, and
a closure that re-validates the credential. It deliberately holds no transport object and no secret.

### Dispatcher (`commands/dispatcher.py`)

For every frame, in this order:

1. parse the JSON (size limit 64 KiB) and validate the envelope;
2. find the command in the registry, or answer `UNKNOWN_COMMAND`;
3. validate `data` against the command's model (`VALIDATION_FAILED`, naming the fields but never echoing values);
4. rate-limit: a per-connection bucket first, then a per-principal one (`RATE_LIMITED` with a retry hint);
5. re-validate the credential, so an expired, revoked or banned token stops working mid-connection and a role change
   applies to the next command;
6. for a command with an idempotency key (`message.create`'s `nonce`), reserve the key. A key that completed returns
   the stored result with `duplicate: true` and runs nothing; a key still in progress answers `CONFLICT` and
   a short retry delay; a failure frees the key so the retry runs;
7. run the handler, build the `ack`, and return the events for the session to publish **after** the ack is sent.

Every failure, including a bug, becomes an `error` frame; `INTERNAL` never carries details. The database-backed
steps (credential re-check, idempotency store) and the handlers' service calls run in a worker thread
(`asyncio.to_thread`) so one slow query does not stall every connection. Anything that touches loop-owned state
(subscriptions, sequence counters) stays on the loop. `ConnectionContext.access_version` guards the gap this opens:
it is bumped whenever access may change under a connection, and a check that ran in a worker thread is repeated
if it moved while it ran, so a result computed from stale permissions is never acted on.

### Handlers (`commands/handlers.py`)

One small function per command. It unpacks the validated payload, calls a service, and returns the result plus the
events. No business rules live here. The registry (`build_registry`) is a dict from command name to
`CommandSpec(name, schema, handler, idempotency_key?)`; adding a command means adding a schema, a handler and a line
in that list, then a fixture and a test.

### Uploads (`uploads/staging.py`, `services/attachments.py`)

Files sent over the socket wait in `UploadStaging` between `upload.begin` / `upload.chunk` and the `message.create`
that names them. The store is per process and touched only from the event loop. It enforces what the client is not
trusted to: the size cap, in-order chunks that add up exactly, expiry (ten minutes), a limit per principal and for the
process, and ownership (`NOT_FOUND` for anyone else's upload). `message.create` then hands the files to
`services/attachments.store_attachments`, the very function the HTTP route uses, so type rules, limits and image
placeholders cannot differ between the two paths. Uploads are discarded only after the message exists, so a send that
storage refused can be retried with the same ids.

### Services (`services/`)

`MessageService` owns the rules for creating, editing and deleting messages and reactions, and for reading recent
history (`events.resync`). A method takes a `Principal` and returns a `ServiceResult`: the value for the caller and a
list of `DomainEvent` objects describing what changed. **A service never publishes.** The HTTP routes that remain
(sending with files) call the very same methods, so the rules exist once.

### Authorizer and principals (`principals/`)

A `Principal` is the validated actor: a user or a bot, with its effective `privileges`. For a bot, that is the
owner's privileges intersected with the scopes the bot was granted, so a bot can never do more than its owner or more
than it was given. The `Authorizer` answers the questions services and handlers ask (`require_send`,
`require_edit`, `can_subscribe`, `require_not_timed_out`). Existence is not disclosed: a channel you may not see
answers the same as one that does not exist.

### Publisher (`events/publisher.py`)

Turns committed `DomainEvent`s into `event` frames. Each channel has a counter, so every channel event gets a
`seq`, and every frame carries the process `epoch`. A client that sees a gap in `seq`, or a different `epoch`, may
have missed events and resynchronises with `events.resync`. Delivery is at-least-once from the client's point of
view, so clients treat events as idempotent by event id and entity id. `EventPublisher` is the seam where a message
broker would go; today `InProcessPublisher` hands frames to the connection manager of this one process.

Sequence numbers do not go backwards across restarts. Each channel's counter starts from a persisted high-water mark
(table `channel_event_seq`) and reserves new numbers in blocks of 64, so a database write happens once per block, not
once per event. After a restart a channel skips at most one block; clients see that as a gap and resync, and `epoch`
changes with every process so they resync anyway. A number is never reused for a different event.

A failed fan-out is logged and counted (`publish_failures`) but never undoes the commit: the data is already saved,
and clients heal by resyncing. That is also what covers a crash between a commit and its publication: the message is
in the history, `events.resync` returns it, and a reconnecting client always resyncs. The database is the log, so
there is no separate outbox to keep consistent.

### Connection manager (`websocket/websocket_manager.py`)

Knows the open sessions: who they belong to, which channels they are subscribed to, how many each user and address
holds. It delivers an event to every session subscribed to the channel, re-checking at delivery time that a private
channel is still allowed, so a revoked privilege stops events at once. It also delivers per-user events
(notifications, DM events, typing in DMs), and `refresh_channel_access` / `revalidate_subscriptions` drop or grant
subscriptions when a channel's visibility, its members or a role change.

## One command, end to end

`message.create` with a `nonce`:

1. `ws_protocol` reads the frame and calls `dispatcher.dispatch(ctx, text)`.
2. The dispatcher validates it, spends rate-limit tokens, re-validates the credential and reserves
   `(principal, "message.create", nonce)`.
3. `message_create` calls `MessageService.create(principal, channel_id, content, ...)` in a worker thread.
4. The service checks the principal may send in the channel and is not timed out, cleans and stores the message,
   and builds the `message.created` event (plus mention, reply and notification events).
5. The handler returns `{message}` and the events; the dispatcher stores the result under the nonce, builds the `ack`
   and returns both.
6. `ws_protocol` sends the `ack`, then `publisher.publish_all(events)`.
7. The publisher numbers the channel event and asks the connection manager to deliver it; every subscribed session,
   including the sender's, receives `message.created`.

If the connection drops after step 5 and before the sender reads the `ack`, the sender retries with the same
`nonce` and gets the stored result with `duplicate: true`: one message, not two.

## Observability

`GET /api/v1/system/instance-health` has a `realtime` object:

```json
"realtime": {
  "protocol_versions": [1],
  "connections": 12,
  "counters": { "connections_opened": 40, "commands.message.create.ok": 311, "latency_ms_total.message.create": 5120, "...": 0 }
}
```

`connections` is the number of open sockets right now. `counters` are process-lifetime totals kept in memory (they
reset on restart). Names are listed here; a counter that has never fired is simply absent.

| Counter | Counts |
|---|---|
| `connections_opened` | Sessions that finished the handshake and received `hello`. |
| `connections_closed` | Sessions that ended, for any reason. `connections_opened - connections_closed` is the number of live sessions. |
| `connections_rejected` | Handshakes refused: unsupported version, bad credential, or one of the limits (10 sockets per account, 50 per address, 10,000 per process). |
| `commands.<name>.<outcome>` | Commands by name and result. `<outcome>` is `ok`, `duplicate`, or a lower-cased error code (`validation_failed`, `permission_denied`, `rate_limited`, `internal`, ...). |
| `latency_ms_total.<name>` and `latency_count.<name>` | Total milliseconds and number of runs per command; divide for the mean. |
| `duplicate_commands` | Commands answered from the idempotency store (completed) or refused as in progress. A steady trickle is normal after reconnects. |
| `rate_limited` | Commands refused by the per-connection or per-principal limit. |
| `validation_failures` | Frames that were malformed, unknown, or failed payload validation. |
| `authorization_failures` | Commands refused for permission or an invalid credential. A burst may be an attack or a bot with the wrong scopes. |
| `events_delivered` | Event frames written to sockets (one event to five sessions counts five). |
| `delivery_failures` | Event frames that could not be written to a socket; the client resyncs when it reconnects. |
| `publish_failures` | Committed changes whose fan-out raised. Should stay at zero; investigate any. |

Useful reads: a rising `delivery_failures` with a flat `connections` means sockets are dying without closing;
`rate_limited` climbing for one command points at a misbehaving client; `internal` outcomes under `commands.*` are
bugs, and each one is logged with its stack trace (without the payload).

## Where things live

| Concern | Module |
|---|---|
| Wire models and error codes | `pufferblow/api/protocol/` |
| Socket session, limits, housekeeping frames | `pufferblow/api/routes/ws_protocol.py` |
| Header and subprotocol credentials | `pufferblow/core/header_auth.py` |
| Dispatcher, rate limiting, idempotency | `pufferblow/api/commands/` |
| Handlers and the command registry | `pufferblow/api/commands/handlers.py` |
| Message rules | `pufferblow/api/services/messages.py` |
| Principals and authorization | `pufferblow/api/principals/` |
| Publisher, sequence numbers, epoch | `pufferblow/api/events/publisher.py` |
| Open sessions, delivery, access refresh | `pufferblow/api/websocket/websocket_manager.py` |
| Counters | `pufferblow/api/commands/metrics.py` |
