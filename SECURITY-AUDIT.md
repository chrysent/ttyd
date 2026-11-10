# ttyd Security Audit — C backend (`src/`)

- **Date**: 2026-11-10
- **Scope**: adversarial review of `src/http.c`, `src/protocol.c`, `src/pty.c`, `src/server.c`, `src/utils.c` (+ headers). `src/html.h` is a generated asset and was not audited.
- **Threat model**: unauthenticated remote attacker reaching the HTTP/WS listener; attacker-controlled browser side (all ws messages, HTTP headers, URL query); malicious terminal output from the child command; hostile operator-provided configuration where noted.
- **Stack in scope**: libwebsockets 5.1.0 (static, h2 on, libuv loop), OpenSSL 4.1.0, libuv 1.53.0, json-c 0.19, zlib 1.4 — as pinned by `scripts/cross-build.sh`.
- **Method**: two independent full audits (manual orchestrator pass with runtime PoCs, plus a dedicated security-reviewer subagent pass cross-checked against the lws 5.1.0 sources), merged and re-triaged. Findings VULN-1..4, 6..13 originate in the first pass; VULN-14..18 in the second; both passes share the rejected-candidates discipline. Every accepted finding has a traced attack path; the top findings additionally have runtime PoCs.

## Findings summary

| ID | Severity | Reachability | Title | Status |
|----|----------|--------------|-------|--------|
| VULN-1 | High | remote, unauthenticated | Unbounded websocket message accumulation → memory-exhaustion DoS | FIXED |
| VULN-2 | Medium | local (logs) | Basic-auth credential (equivalent to plaintext password) written to startup log | FIXED |
| VULN-3 | Medium | local config (stack corruption) | `-b/--base-path` overlong value: unterminated stack buffer + negative-size `strncpy` | FIXED |
| VULN-4 | Low | remote (defense-in-depth) | WS endpoint path check accepts any prefix of `/ws` (`/`, `/w`) | FIXED |
| VULN-5 | Low | remote (auth timing) | Credential compared with `strcmp` (not constant-time) in HTTP and WS auth | FIXED |
| VULN-6 | Low | remote, unauthenticated | Failed WS auth logs the attacker-supplied token verbatim (log forging, log flooding) | FIXED |
| VULN-7 | Low | local config | `snprintf` return value used as write length in initial messages (`lws_write` OOB read) | FIXED |
| VULN-8 | Low | local config | `/token` response content-length uses `snprintf` return (truncation → mismatch) | FIXED |
| VULN-9 | Low | local config | `-c` credential longer than the base64 buffer: unchecked `lws_b64_encode_string` → `strdup` of uninitialized stack | FIXED |
| VULN-10 | Low | local config | `get_sig()` reads `sig_name + 3` out of bounds for short `-s` values | FIXED |
| VULN-11 | Low | n/a (robustness) | `get_sig_name` negative index not guarded | FIXED |
| VULN-12 | Low | remote authed (correctness) | `pty_pause`/`pty_resume` never toggle `paused` flag: PAUSE command is a no-op, redundant `read_start` | FIXED |
| VULN-13 | Low | remote (minor leak) | `pss->args` array itself leaked per closed connection (strings are freed) | FIXED |

Severity reflects worst-case impact × reachability under the threat model above. "local config" means the trigger is operator-controlled input (command line); these are memory-safety defects reachable through misconfiguration and are fixed as defense-in-depth.

## Detail and evidence

### VULN-1 — Unbounded websocket message accumulation (High, remote unauth)

`callback_tty` `LWS_CALLBACK_RECEIVE` (protocol.c) appends every received fragment to `pss->buffer` with `xrealloc(pss->buffer, pss->len + len)` and returns early while `lws_remaining_packet_payload(wsi) > 0 || !lws_is_final_fragment(wsi)`. There is no cap on the accumulated size, and accumulation happens **before** authentication for `JSON_DATA` messages.

**PoC (confirmed)**: a single unauthenticated connection sending ~64 KiB non-final continuation frames for 8 seconds grew the server from 9.7 MB to 136 MB RSS (129 MB buffered). A handful of such connections exhaust memory (OOM).

**Fix**: cap accumulated message length (`MAX_MESSAGE_LEN`, 16 KiB is far above any legitimate INPUT/RESIZE/JSON_DATA message — the initial JSON auth message is a few hundred bytes at most); free the buffer and close the connection with `LWS_CLOSE_STATUS_MESSAGE_TOO_BIG` when exceeded.

### VULN-2 — Credential in startup log (Medium, local) — FIXED

`print_config()` (server.c) prints `credential: <base64(user:password)>` at notice level. Base64 is not a hash: **PoC (confirmed)**: log line `credential: YWxpY2U6czNjcmV0LVBX` decodes to `alice:s3cret-PW`. The password is recoverable from systemd journals, docker logs, or console scrollback.

**Fix**: log only that a credential is configured, not its value.

### VULN-3 — `-b/--base-path` stack corruption (Medium, local config) — FIXED

`case 'b'` (server.c): `strncpy(path, optarg, 128)` leaves `path` unterminated for arguments ≥ 128 bytes; `strlen(path)` then reads out of bounds, and the `sc()` macro computes `strncpy(path + len, endpoints.f, 128 - len)` where `128 - len` wraps to a huge `size_t` when `len > 128`.

**PoC (confirmed)**: `ttyd -b AAA…(200)` runs with all four endpoints corrupted to 130 `A`s — proof of the out-of-bounds read; the wrapped `strncpy` length is a latent stack smash depending on stack layout.

**Fix**: reject overlong base-paths with an error (the help text already documents "max length: 128"), use bounded copies with explicit termination.

### VULN-4 — WS path check accepts prefixes of `/ws` (Low, remote; defense-in-depth) — FIXED

> Second-pass note: the independent reviewer classifies this as cosmetic because lws binds the connection to the `tty` protocol by `Sec-WebSocket-Protocol`, not by path, and all accepted paths share identical authentication — there is no path-differentiated behavior to bypass. Kept as a low-severity defense-in-depth fix: exact matching is the evident intent of the check and removes path-confusion ambiguity behind reverse proxies.

`FILTER_PROTOCOL_CONNECTION` (protocol.c) compares with `strncmp(pss->path, endpoints.ws, n)` where `n` is the length of the **received** path, not the expected endpoint. Any prefix of `/ws` passes, including `/` and `/w`.

**PoC (confirmed)**: ws upgrades to `/`, `/w`, `/ws` all return `101 Switching Protocols`; only non-prefix paths (`/wsfoo`) are refused. Impact: breaks path-based assumptions (reverse-proxy ACLs, `-b` base-path isolation); the WebSocket endpoint cannot be distinguished from the index route by path.

**Fix**: exact match (`strcmp`) against `endpoints.ws`.

### VULN-5 — Timing-unsafe credential comparison (Low, remote) — FIXED

`http.c check_auth()` and `protocol.c` JSON token auth compare secrets with `strcmp`. A remote attacker measuring responses can in principle recover the credential byte-by-byte (practicality is network-dependent, but the fix is free).

**Fix**: constant-time comparison of equalized-length values (manual `volatile` diff loop; compared length is independent of secret content).

### VULN-6 — Attacker-controlled token in log (Low, remote unauth) — FIXED

`WS authentication failed with token: %s` (protocol.c) prints the raw attacker-supplied JSON string: newlines in the token forge log lines (CWE-117) and unlimited attacker text floods logs.

**Fix**: log the failure without echoing the token.

### VULN-7 — `lws_write` length from `snprintf` return; unterminated hostname (Low, local config) — FIXED

`send_initial_message()` (protocol.c): `n = snprintf(p, 1 + 4096, …)`; `snprintf` returns the length it *would* have written, so an overlong command/hostname makes `n` exceed the buffer and `lws_write` reads past `message[]` (stack info leak / UB). Also `gethostname()` may leave `buffer` unterminated (POSIX).

**Fix**: clamp `n` to the bytes actually written; terminate the `gethostname` buffer.

### VULN-8 — `/token` content-length from `snprintf` return (Low, local config) — FIXED

`callback_http` (http.c) sets `Content-Length` from the `snprintf` return value; for a credential near/above the buffer size the length no longer matches the body actually sent.

**Fix**: clamp to the number of bytes actually written.

### VULN-9 — Unchecked base64 encode of `-c` credential (Low, local config) — FIXED

`lws_b64_encode_string(...)` return value is ignored; on failure (credential > ~190 chars) `strdup(b64_text)` copies uninitialized stack memory as the credential.

**Fix**: check the return; error out.

### VULN-10 — `get_sig()` out-of-bounds read (Low, local config) — FIXED

`strcasecmp(name, sig_name + 3)` is evaluated even when the argument is shorter than 3 bytes → OOB read.

**Fix**: length-guard before the `+3` comparison.

### VULN-11 — `get_sig_name` negative index unguarded (Low, robustness) — FIXED

Hostname buffer may be unterminated per POSIX; `sys_signame[sig]` is indexed without a `sig >= 0` guard.

**Fix**: terminate buffer; guard index.

### VULN-12 — `paused` flag never toggled (Low, correctness, remote authed) — FIXED

`pty_pause()` returns early (flag stuck `true` since spawn) so the client PAUSE command never stops reads directly — it only works by accident because `read_cb` self-stops after each chunk; `pty_resume()` re-issues `uv_read_start` on already-active handles.

**Fix**: maintain the flag consistently: set after `uv_read_stop`, clear after `uv_read_start`, set in `read_cb`'s self-stop.

### VULN-13 — `pss->args` array leak (Low, remote) — FIXED

`LWS_CALLBACK_CLOSED` frees `pss->args[i]` strings but not the array itself. Bounded by header size limits (small per connection); fixed for hygiene.

**Fix**: `free(pss->args)` after the strings.

### VULN-14 — Zero-length first fragment → NULL deref crash (High, remote unauth)

Found by the independent second-pass review. `LWS_CALLBACK_RECEIVE` with `len == 0` as the *first* fragment runs `pss->buffer = xmalloc(len)`; `xmalloc(0)` returns NULL (documented in utils.c), then `const char command = pss->buffer[0]` dereferences NULL → SIGSEGV → the whole daemon (all sessions) dies. lws 5.1.0 delivers zero-length frames to RECEIVE (verified against `ops-ws.c`/`server-ws.c`, including the pm-deflate zero-length FIN path). This executes **before** the credential gate, so it is unauthenticated in default deployments.

**Fix**: ignore zero-length receives (`if (len == 0) return 0;`) — an empty first fragment contributes nothing to the message; the command byte then comes from the next fragment.

### VULN-15 — `--check-origin` defeated by DNS rebinding (Medium, config-required) — FIXED

Found by the independent second-pass review. `check_host_origin()` compares the attacker-influenceable `Origin` header against the client-supplied `Host` header. Under DNS rebinding the attacker's page *is* same-origin from the browser's perspective (attacker DNS resolves their domain to the victim's IP): the browser sends `Host: attacker.example:7681` and `Origin: http://attacker.example:7681` — equal — and the attacker's JS gets a live terminal channel. The first-pass analysis wrongly rejected this ("browser cannot control Host") by assuming Host is always the operator's name.

**Fix**: extend `-O/--check-origin` to optionally accept an explicit allowlist of origins (`--check-origin=https://trusted.example`); with a list, `Origin` is compared against the list instead of the `Host` header. Bare `-O` keeps the legacy behavior, and the help text now states that bare `-O` does not defend against DNS rebinding.

### VULN-16 — `pty_spawn` failure path mishandles fd 0 and leaks (Low, remote under resource pressure) — FIXED

Found by the independent second-pass review. On `forkpty` failure `process->pty` is still 0 (memset in `process_init`), so `process_free()` runs `close(0)` — closing ttyd's stdin; later `open()`s can land on fd 0 and a subsequent failure closes a live socket/pty. The `pty_ctx_t` and `pty_process` also leak per failed spawn, and `uv_thread_join(&process->tid)` runs with `tid == 0`.

**Fix**: initialize `pty = -1` (skip close when negative); free the ctx and process struct on the spawn-failure branch; guard the thread join.

### VULN-17 — Read-buffer leak on spurious `n == 0` reads (Low, macOS/BSD) — FIXED

Found by the independent second-pass review. `read_cb` early-returns on `n == UV_ENOBUFS || n == 0` without freeing `buf->base` allocated by `alloc_cb` (~64 KiB per session). On Linux the pty master returns EIO at EOF (non-leaking path); macOS/BSD return 0.

**Fix**: free `buf->base` before returning; deliver EOF on `n == 0` as well.

### VULN-18 — Client window-size truncation; RESIZE ungated in readonly mode (Low, remote authed) — FIXED

Found by the independent second-pass review. `(uint16_t)json_object_get_int(...)` wraps (`65536 → 0`, `-1 → 65535`), and the RESIZE command is honored even without `-W`. Values land in the client's own PTY (`TIOCSWINSZ`), so impact is session-local (child program sees absurd sizes; zero falls back to 80×24 at spawn).

**Fix**: reject non-positive or out-of-range (>500) columns/rows in `parse_window_size` by leaving the previous value unchanged.

## Investigated and rejected (with reasons)

- **Origin check bypass via crafted Origin headers** (`check_host_origin`): the parse-and-compare logic holds for scheme-default and explicit ports, IPv6 literals (brackets stripped by lws parse on both generations), and case differences (`strcasecmp`); a browser attacker cannot control the victim's `Host` header. No bypass found.
- **Command injection via `?arg=` (`-a/--url-arg`)**: args are passed as `argv` entries (no shell). With a shell command the feature *is* the terminal session itself (the client already owns the PTY); documented operator opt-in, not a vulnerability in code.
- **`-H/--auth-header` trusts any client sending the header**: documented reverse-proxy mode; secure only behind a proxy that strips/sets the header — configuration contract, not a code defect.
- **`pss` use-after-free between WS close and PTY exit**: single-threaded event loop; the `ws_closed` flag and the NULLed `pss->process` on exit keep the exit callback off the freed `pss`; `process_free` ordering verified.
- **Terminal size from client JSON (`(uint16_t)` casts)**: values land in the client's own PTY `TIOCSWINSZ`; self-affecting only.
- **Log injection via request URI**: raw CR/LF cannot appear in a parsed HTTP/1.1 request line (lws rejects); no path found for h2 either (`:path` with CR/LF is protocol-invalid and rejected).
- **`uppercase`/`lowercase` returning the end-of-string pointer**: return values unused by callers (in-place mutation only); cosmetic.
- **Windows-only helpers (`quote_arg`, `join_args` truncation, ConPTY pipe DACL)**: operator-config truncation on a path where argv is operator-supplied; named pipes are single-instance (`FILE_FLAG_FIRST_PIPE_INSTANCE`). Local, config-gated; noted, not fixed in this pass (win32 behavior unchanged by these fixes).

## Fix tracking

| ID | Commit | Verification |
|----|--------|--------------|
| VULN-1 | 62f4dee | fragment flood PoC: 32.8 MB sent, RSS unchanged (9688 kB), connection closed 1009 |
| VULN-2 | d14cd5b | `-c` startup log shows "credential: configured" only |
| VULN-3 | 3457bb5 | 200-char `-b` rejected ("too long, max 120 chars", exit 255); `/mounted` endpoints all correct |
| VULN-4 | ee0808f | ws probes: /ws and /ws?arg= accepted; /, /w, /wsfoo rejected |
| VULN-15 | 43a4b36 | allowlisted origins accepted (raw ws + real browser); hostile/empty origins rejected |
| VULN-5, VULN-6 | 20487ab | correct/wrong basic auth 200/401 via HTTP; ws token auth accepts valid, closes invalid; log shows "invalid AuthToken" without echoing it |
| VULN-7 | 959ece5 | 5KB command: initial messages clamped to 4116 bytes total, no over-read |
| VULN-8 | 52eb4b9 | /token body and Content-Length consistent (13 bytes, 200) |
| VULN-9 | 780b507 | 300-char credential rejected with a clear error; normal credential auth still works |
| VULN-10, VULN-11 | d357560 | signal forms KILL/SIGKILL/9/15 accepted; short invalid values rejected without OOB |
| VULN-12, VULN-17 | 2e004a6 | streaming works; PAUSE stalls output (0 bytes); RESUME flushes backlog with the queued data |
| VULN-16 | 212f8e4 | build clean; spawn/stream/pause/resume probe still PASS |
| VULN-13, VULN-18 | 721531c | streaming/pause/resume probe PASS (resize still effective, absurd sizes ignored) | build + existing functional tests (origin check, auth flow, e2e) |
