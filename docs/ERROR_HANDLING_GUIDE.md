# PufferBlow — Error Handling Guide for Client Developers

This is the **how-to-build-a-client guide** for working with
PufferBlow's HTTP API errors. It covers the contract, recommended
patterns, federation-aware concerns, and the offline-detection
choreography. If you're after the per-code reference (which code
means what, what HTTP status it ships with), see
[`ERROR_CODES.md`](./ERROR_CODES.md). This doc explains *how to
consume* that reference in a real application.

It's written for:

- People building alternate PufferBlow clients (mobile, desktop,
  CLI, bots).
- Engineers integrating PufferBlow into existing apps.
- The reference PufferBlow web client codebase (mirrors what's
  implemented in `client/app/services/apiError.ts`,
  `apiClient.ts`, `instanceHealth.ts`, `networkStatus.ts`).

## TL;DR

Every error response — regardless of route, regardless of the
status code — has the same JSON shape:

```json
{
  "status_code": 409,
  "error_code": "stickers.alias_taken",
  "message": "Alias ':party_parrot:' is already taken",
  "user_message": "The shortcode ':party_parrot:' is already in use.",
  "details": { "alias": "party_parrot" },
  "request_id": "1c8a3f0e-7d6e-4a3b-8a1e-92b8f1f0d9a2",
  "retry_after_seconds": null
}
```

Three guarantees you can rely on:

1. **`error_code` is stable.** Renames or removals are wire breaks
   and require a deprecation cycle. Pin against the string.
2. **`user_message` is safe to display.** Pre-formatted, no
   placeholders, no PII, written for end users. Show it verbatim.
3. **`request_id` matches `X-Request-ID`.** Either one is a
   support-correlation key — give users a way to copy it.

## 1. The envelope contract

### Required fields (always present)

| Field | Type | Notes |
|---|---|---|
| `status_code` | int | HTTP status; matches the response status line. |
| `error_code` | string | Stable identifier — pin clients against this. |
| `message` | string | Developer-oriented description. May contain technical context. **Don't show to users.** |
| `user_message` | string | Safe to display verbatim. |
| `details` | object | Structured context. May be empty. |
| `request_id` | string \| null | Correlation id. Matches `X-Request-ID`. |
| `retry_after_seconds` | int \| null | Populated for 429s and some 503s. |

### Optional `details` keys

The `details` object is loosely typed — each code documents which
keys it uses. The most common keys to handle:

| Key | When | Example use |
|---|---|---|
| `field` | Validation / form errors | Highlight that specific input |
| `fields` | Multi-field validation | Array of `{field, type, message}` |
| `privilege` | `auth.privilege_denied` | "You need *X* permission to do that." |
| `alias` | `stickers.alias_taken` | "*foo* is already used" |
| `limit` | Range / size errors | "Max *N* characters" |
| `actual` | Range / size errors | "You sent *M*" |
| `host_port` | Network errors | Which instance failed |

### Versioning

The envelope is **additive**: new optional fields may appear in
future versions. Field renames or removals require a version bump
or a deprecation cycle. Clients should ignore unknown fields.

## 2. Decoding errors

The reference web client's `decodeApiError` function (in
`client/app/services/apiError.ts`) is the suggested model. Three
input shapes feed the same decoder:

1. **Canonical envelope** — passed through as-is.
2. **Legacy `{ detail: "..." }`** — older servers / un-migrated
   routes. Synthesize the envelope fields from the status code +
   the detail string.
3. **Network errors / unknown bodies** — collapse to a
   `client.*` or `instance.*` AppError with a sensible default
   message.

The decoder's output is a flat object every call site can consume:

```typescript
interface AppError {
  code: string;             // pin against this
  userMessage: string;      // show to the user
  message: string;          // log this
  details: Record<string, unknown>;
  httpStatus: number;       // 0 = no response (network error)
  requestId: string | null;
  retryAfterSeconds: number | null;
  isFallback: boolean;      // true → envelope was missing
}
```

## 3. Routing decisions by code

The whole point of stable codes is that the UI can switch on them
to make smarter choices than "show a generic toast." Here are the
high-value branches:

### Auto-logout on auth failure

```typescript
if (error.code === "auth.invalid_token" ||
    error.code === "auth.refresh_token_expired" ||
    error.code === "auth.refresh_token_invalid") {
  // Clear stored tokens and bounce to the login screen.
  clearSession();
  navigate("/login");
  return;
}
```

### Highlight specific form inputs

```typescript
if (error.code === "validation.field_required" ||
    error.code === "auth.username_taken" ||
    error.code === "auth.password_too_weak") {
  const field = error.details.field as string;
  setFieldErrors({ [field]: error.userMessage });
  return;  // don't show a banner; the inline error is enough
}
```

### Honor `retry_after_seconds`

```typescript
if (error.retryAfterSeconds) {
  setRetryCountdown(error.retryAfterSeconds);
  disableButton(error.retryAfterSeconds * 1000);
}
```

### Background retry with backoff

```typescript
const RETRYABLE = new Set([
  "rate_limit.exceeded",
  "storage.upload_failed",
  "federation.remote_unreachable",
  "server.internal_error",
  "server.unavailable",
  "client.network_offline",
  "client.network_timeout",
]);
if (RETRYABLE.has(error.code) || error.httpStatus >= 500) {
  scheduleRetry(error.retryAfterSeconds ?? defaultBackoff(attempt));
}
```

### Enumeration resistance (auth)

For sign-in, the server collapses "unknown username" and "wrong
password" into one code (`auth.invalid_credentials`). **Don't try
to be helpful by re-distinguishing them client-side** — that
undoes the protection. The `message` field carries the truth for
server logs; the public surface stays generic.

## 4. UI patterns: where to surface each error

Different errors deserve different UI treatments. Don't toast
everything.

| Error kind | UI pattern | Example codes |
|---|---|---|
| Field-level validation | Inline red border + helper text on the offending input | `validation.field_*`, `auth.username_taken`, `auth.password_too_weak` |
| Action failed (button click) | Toast / snackbar with `userMessage` | `stickers.alias_taken`, `messages.too_long` |
| Permission denied | Toast OR replace the action area with a "not allowed" message | `auth.privilege_denied`, `channels.access_denied` |
| Session expired | Force-redirect to login with a small notice | `auth.invalid_token`, `auth.refresh_token_*` |
| Rate limited | Disable the action + countdown using `retry_after_seconds` | `rate_limit.exceeded`, `auth.account_locked`, `auth.reset_cooldown` |
| Server outage | App-wide banner | `server.unavailable`, `instance.home_unreachable` |
| Device offline | App-wide banner | `client.network_offline` |
| Remote instance unreachable | **Per-instance** badge (rail dot), NOT a banner | `instance.unreachable`, `federation.remote_unreachable` |
| Unhandled crash (500) | Toast with the `request_id` shown so the user can copy it | `server.internal_error` |

## 5. Federation-aware offline detection

This is the part that most non-federated apps don't have to think
about. PufferBlow clients routinely talk to several instances:

- The **home instance** — holds the user's identity, friend graph,
  private channels. If it's down, most features are broken.
- **Joined remote instances** — peers the user has joined. Each
  is independent; one being down should not affect the others.
- **Federation peers** — instances reached transitively via
  ActivityPub (e.g. when DM'ing `alice@remote.example`). Their
  health is even more arms-length.

The single biggest UX failure mode is treating any one of these
failing as "you're offline." Don't do that. The contract carries
four distinct codes so clients can pick the right surface:

| Situation | Code | Surface |
|---|---|---|
| Device has no internet at all | `client.network_offline` | App-wide banner. Disable composer. Pause WS reconnects. |
| Home instance offline (device fine) | `instance.home_unreachable` | App-wide banner naming the host. Most operations will fail. |
| Joined remote offline (others fine) | `instance.unreachable` (scoped to host) | **Per-instance** badge on the rail. Do NOT global-banner this. Other instances continue to work. |
| Federation peer reached through home is offline | `federation.remote_unreachable` | **Per-conversation** inline message. Home is fine; messages to other peers still flow. |

### Recommended detection choreography

1. Maintain a per-host **instance health tracker** keyed by
   `host_port`. Update it on every request:
   - Success → `markHealthy(host)`
   - Failure → `markUnhealthy(host, error.code)`
2. Maintain a separate **device-level network status** singleton.
   Read `navigator.onLine` (or the platform equivalent) and listen
   to `online` / `offline` events.
3. Don't let either signal lie about the other:
   - `navigator.onLine === false` → emit `client.network_offline`,
     don't pollute instance health (the device is the problem,
     not the instance).
   - `navigator.onLine === true` but the home host won't respond →
     emit `instance.home_unreachable`, mark just that host
     unhealthy.
   - `navigator.onLine === true` but a remote host won't respond →
     emit `instance.unreachable`, mark just that host unhealthy.
4. WebSocket reconnect should subscribe to the network-status
   singleton:
   - On `offline`: cancel pending reconnect timers, close the
     current socket, set a "suspended" flag.
   - On `online`: reset the attempt counter, reconnect
     immediately. Don't burn exponential-backoff retries during
     the offline window.
5. The composer should disable sends on `offline`. Don't queue
   messages and pretend they'll send — show the user the truth.

### What "the instance is unhealthy" actually means

A single 500 doesn't mean the instance is down. Auth failures
(401, 403) don't mean the instance is down — they mean THIS
request was refused. Useful heuristic:

- Promote a host to `unreachable` after **3 consecutive** failures
  that are network-level OR 5xx OR explicit `instance.unreachable`.
- Don't count auth / permission / validation failures against
  health — they're not evidence the instance is broken.
- Demote `unreachable` back to `healthy` on the next successful
  response.

## 6. Logging + support correlation

Every error response carries `request_id` (also as
`X-Request-ID`). Two things you should do with it:

1. **Log it client-side** alongside the error so you can
   correlate when debugging. Include it in any crash reports.
2. **Surface it on serious errors** (`server.internal_error`,
   `server.unavailable`) so users can paste it into bug reports.
   A copy-button next to it goes a long way.

Example:

```typescript
if (error.httpStatus >= 500) {
  showToast({
    title: error.userMessage,
    body: `Reference: ${error.requestId}`,
    actions: [{ label: "Copy ID", onClick: () => copy(error.requestId) }],
  });
}
```

## 7. Backward compatibility

For routes that haven't been migrated to the new envelope yet, the
server's global exception handler converts plain `HTTPException`
into the envelope shape automatically (mapping by status code).
You'll see `isFallback: true` on those — clients can use that to
log "we hit a non-migrated route" for telemetry, but the user
experience is the same.

For older server builds that predate the envelope entirely:

- The body will look like `{ "detail": "..." }`.
- `decodeApiError` synthesises an envelope from the status + the
  detail string.
- The `error_code` will be derived from the status (e.g. 404 →
  `resource.not_found`).
- `isFallback` will be `true`.

Don't ship custom logic for the legacy shape — fall through the
decoder and treat it like any other error.

## 8. Adding a new error code (server contributors)

When adding a new failure mode that clients should distinguish:

1. Pick a dotted name: `area.condition`. The area is an existing
   feature namespace (`stickers`, `friends`, `channels`,
   `auth`, ...) or a new one if you're adding a feature.
2. Add the constant to `ErrorCode` in
   `pufferblow/api/errors/codes.py`.
3. Add an `ErrorSpec(...)` entry to `ERROR_REGISTRY`:
   - `status` — HTTP status the envelope ships with.
   - `user_message` — default human-facing copy.
   - `retryable` — does it make sense to auto-retry?
   - `description` — one-paragraph explainer for the docs.
4. Add a row to `ERROR_CODES.md` under the appropriate section,
   matching the default `user_message` in the spec.
5. Migrate the raise site:

   ```python
   from pufferblow.api.errors import ApiError, ErrorCode
   raise ApiError(
       ErrorCode.YOUR_NEW_CODE,
       message=f"Specific reason for logs: {context}",
       details={"field": "username", "limit": 32},
   )
   ```

6. If the new code is meant to be acted on differently from
   existing codes (auto-logout, field highlight, retry), update
   this guide's pattern tables so client developers know.

Renaming or removing a code is a **wire break**. Either bump the
API version or run a parallel deprecation window with both old
and new codes.

## 9. Suggested AppError shape (TypeScript)

If you're building a new client and want a head-start, this is
the shape we recommend. It mirrors the reference web client's
`apiError.ts`:

```typescript
interface AppError {
  code: string;
  userMessage: string;
  message: string;
  details: Record<string, unknown>;
  httpStatus: number;
  requestId: string | null;
  retryAfterSeconds: number | null;
  isFallback: boolean;
}

// Predicates that turn out to be useful repeatedly:
function isAuthError(e: AppError): boolean { /* auth.* + 401 fallback */ }
function isRetryableError(e: AppError): boolean { /* see §3 */ }
function isValidationError(e: AppError): boolean { /* validation.* + 400/422 */ }
function getFieldErrors(e: AppError): {field: string, message: string}[] { /* read details.fields */ }
```

## 10. Cheat sheet

| You want to... | Read this field | Action |
|---|---|---|
| Decide whether to show this error | `error.code` | Switch by code; default-toast for unhandled |
| Show a message to the user | `error.userMessage` | Display verbatim |
| Log this server-side reason | `error.message` | Include in logs / Sentry |
| Highlight a form input | `error.details.field` | Set inline field error |
| Show multiple field errors | `error.details.fields` | Iterate and set each input |
| Schedule a retry | `error.retryAfterSeconds` | Backoff with `setTimeout` |
| Tell the user how to report this | `error.requestId` | Show + copy button |
| Distinguish offline vs server down | `error.code` starts with `client.` vs `instance.` vs `server.` | See §5 |

---

If anything in this guide doesn't match what you observe in the
wire surface, that's a bug — please open an issue. The contract
is what's shipped, the docs reflect it.
