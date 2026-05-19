# theyOS LLM proxy (codename Aurora)

A host-side multiplexer that lets any claw use any LLM provider — local
models, cloud API keys, or CLI-OAuth subscriptions — through a single
loopback OpenAI-compatible endpoint. Credentials never enter the claw.

> **Implementation status:** Slices 0-7 of the
> [Aurora plan](https://github.com/soyeht/theyos/blob/codex/ollama-theyos-integration/admin/rust/llm-proxy-rs/)
> are merged into `codex/ollama-theyos-integration`. Slice 8 (this doc) is
> the wrap-up — the proxy itself is fully tested and run-ready.

## What it does

```
┌──────────────────────────────────────────────────────┐
│  theyos-llm-proxy   (host)                           │
│  ┌──────────────────────────────────────────┐        │
│  │  axum @ 127.0.0.1:18900                  │        │
│  │   /health                                │        │
│  │   /v1/models                             │        │
│  │   /v1/chat/completions                   │        │
│  │   /v1/c/<claw_type>/models               │        │
│  │   /v1/c/<claw_type>/chat/completions     │        │
│  │   /admin/catalog                         │        │
│  └────────────────┬─────────────────────────┘        │
│                   │                                  │
│  ┌────────────────┴───────────────┐                  │
│  │  active provider router        │                  │
│  └────────────────┬───────────────┘                  │
│      │            │             │                    │
│ ┌────▼──┐   ┌─────▼─────┐  ┌────▼──────┐             │
│ │ local │   │ cloud-key │  │ cli-oauth │             │
│ │ forw  │   │ + auth    │  │ subprocess│             │
│ │       │   │ inject    │  │ (claude)  │             │
│ └───┬───┘   └─────┬─────┘  └─────┬─────┘             │
└─────┼─────────────┼──────────────┼───────────────────┘
      │             │              │
ollama/llamacpp/mlx  api.openai    local
  (loopback)         api.anthropic claude CLI
                     api.z.ai      (subprocess)
                     ...
      ▲
      │
 reverse SSH tunnel from claw guest
      │
┌─────┴────────────────────────────────────────┐
│  any claw                                    │
│  reads THEYOS_LLM_OPENAI_BASE_URL=           │
│        http://127.0.0.1:18900/v1/c/<type>    │
│  doesn't care what's behind it               │
└──────────────────────────────────────────────┘
```

The architecture decision lives in
[`memory/project_llm_host_proxy_architecture.md`](../). Short version: the
trust boundary is the VM guest. Anything that touches a real credential
runs on the host, never inside the claw.

## Provider matrix

The same wire format works for every combination. Adding a new claw =
zero proxy changes. Adding a new provider = one impl of the `Provider`
trait + one catalog entry.

22 providers in the catalog, grouped by class:

- **Local OpenAI-compat (3)** — ollama, llamacpp, mlx
- **Cloud API key (15)** — openai, anthropic, google, xai, deepseek, zai,
  moonshot, qwen, minimax, groq, cerebras, together, mistral, nvidia,
  openrouter
- **CLI-OAuth subscription (4)** — claude-cli, openai-codex,
  google-gemini-cli, opencode-cli

Every entry produces an instantiable `Provider` from
`build_provider_registry` — confirmed by a catalog completeness test
(`tests/catalog.rs::cli_oauth_entries_cover_all_four_flavors` +
`every_catalog_entry_produces_an_instantiable_provider_config`).

The frontend [`/models` page](../admin/frontend/src/pages/ModelsLivePage.tsx)
is the live UI for this switchboard, backed by `/api/v1/llm/*` on
server-rs (which reverse-proxies to the host-side
`theyos-llm-proxy` daemon). The mock design twin at
`/models-preview` stays untouched for visual iteration.

## Provider classes

| Class | Crate impl | Catalog kind | Examples |
|---|---|---|---|
| Local model server | `OpenAiCompatProvider` (passthrough) | `openai-compat` | ollama, llamacpp, mlx |
| Cloud OpenAI-compat API | `OpenAiCompatProvider` (with Bearer injection) | `openai-compat` | openai, deepseek, zai, moonshot, qwen, minimax, openrouter, groq, cerebras, together, mistral, nvidia, xai |
| Anthropic Messages API | `AnthropicApiProvider` (shape translation) | `anthropic-api` | anthropic |
| CLI-OAuth subprocess | `ClaudeCliProvider` (subprocess) | `cli-oauth` | claude-cli (Claude Pro/Max via local `claude` binary) |

OpenAI Codex OAuth, Gemini CLI, and GitHub Copilot follow the same
`cli-oauth` pattern with different binaries — deferred to a follow-up
slice because each needs verification against the actual CLI binary.

## Threat model

The proxy is the only theyOS component that handles raw provider
credentials.

1. **Credentials live in the host keystore** (`keystore-rs`). The
   backend is picked automatically per host capability — see
   [Keystore backends](#keystore-backends) below.
2. **The keystore service prefix is `com.soyeht.theyos`** with account
   labels `llm.api_key.<provider>` for API keys.
3. **Credentials are read once at proxy startup** and held in memory by
   each `Provider` instance. No per-request keystore round-trip.
4. **Credentials are never logged.** The audit log records who used
   what model when, but never the message content or any auth material.
5. **The claw never sees a real credential.** Even when a claw routes
   through `provider=proxy`, the contract sets `THEYOS_LLM_API_KEY` to
   the placeholder `theyos-proxy-placeholder`. Prompt-injection in the
   claw cannot exfiltrate keys because the only path back to the host
   is the reverse SSH tunnel.
6. **The claw never sees the internet.** It talks to loopback. The
   tunnel maps `guest:18900 → host:18900`. The proxy then talks to the
   real provider.
7. **The admin surface is write-only for credentials.** The admin HTTP
   API at `/api/v1/llm/providers` lets you add, rotate, test, and
   remove provider credentials, but there is no read endpoint — the
   `ProviderSummary` response exposes only `has_credential: bool` and
   the account label, never the secret value. A stolen admin session
   cookie can **use** providers (audited) but cannot **exfiltrate**
   them. Regression test:
   [`list_providers_never_returns_credential_value`](../admin/rust/llm-proxy-rs/tests/admin_providers.rs).

Per the memory note: "claws are untrusted code; the trust boundary
lives outside the VZ/Firecracker guest."

### Keystore backends

The proxy chooses the best backend the host can support. Override with
`THEYOS_LLM_KEYSTORE`; the supported values are `auto` (default),
`file`, `system`, and `tpm`.

| Host | `auto` resolution | Encryption at rest | Backup migration |
|------|-------------------|--------------------|------------------|
| **macOS** (Apple Silicon / T2) | Login Keychain (`SystemKeystore`) | wrapped by Secure Enclave | restorable on another Mac with same Apple ID |
| **Linux + TPM2** | `systemd-creds --with-key=auto+tpm2` (`TpmKeystore`) | sealed to host TPM PCRs | seal breaks on clone-disk / different host |
| **Linux without TPM2** | `0600` file (`FileKeystore`) | filesystem ACL only | clone-disk restores credentials |
| **macOS pre-T2 Intel** | Login Keychain (`SystemKeystore`) | software encryption only | restorable on another Mac |

The TPM2 path on Linux is the main hardening for production
(`bignix`): the sealed blob is bound both to the host's TPM and to the
account name, so neither moving the file across hosts nor renaming it
inside a host yields a usable credential. Decrypt failures surface as
`KeystoreError::Io` with a hint pointing at the systemd-creds error
output — the operator must re-add the credential.

The `0600` file backend has no encryption at rest beyond filesystem
permissions. It exists as a fallback for hosts without a TPM and as a
test path; production hosts should provision a TPM and let `auto`
upgrade them.

## Per-claw routing

Two URL paths surface on the proxy:

- `POST /v1/chat/completions` — uses the **default active profile** at
  `~/.theyos/llm-profiles/default.toml [active]`.
- `POST /v1/c/<claw-type>/chat/completions` — uses the **per-claw
  overlay** at `~/.theyos/llm-profiles/<claw-type>.toml [active]` if it
  exists, otherwise falls back to the default.

The claw bakes its own claw-type into the URL via the bootstrap
contract — it doesn't pick the provider, it just stamps the request so
the host knows which override to apply.

To route, e.g., openclaw at Claude Code subscription and hermes-agent
at a local ollama, the host runs:

```sh
# Set the global default — used by hermes-agent (no overlay).
curl -sS -X PUT http://127.0.0.1:18900/admin/llm/active \
  -H 'content-type: application/json' \
  -d '{"provider":"ollama","model":"llama3.1"}'

# Add a per-claw overlay for openclaw.
curl -sS -X PUT http://127.0.0.1:18900/admin/llm/active/openclaw \
  -H 'content-type: application/json' \
  -d '{"provider":"claude-cli","model":"claude-sonnet-4-7"}'
```

Both claws then run with `THEYOS_LLM_PROVIDER=proxy` and hit the same
proxy port; the proxy resolves provider per-claw.

## TOML profiles

`~/.theyos/llm-profiles/default.toml`:

```toml
[active]
provider = "ollama"
model    = "llama3.1"

[providers.ollama]
kind      = "openai-compat"
base_url  = "http://127.0.0.1:11434/v1"
models    = ["llama3.1", "qwen3:4b"]

[providers.zai]
kind                = "openai-compat"
base_url            = "https://api.z.ai/api/coding/paas/v4"
credential_account  = "llm.api_key.zai"
models              = ["glm-5.1", "glm-4.7"]

[providers.anthropic]
kind                = "anthropic-api"
base_url            = "https://api.anthropic.com"
credential_account  = "llm.api_key.anthropic"
models              = ["claude-opus-4-7", "claude-sonnet-4-7", "claude-haiku-4-5"]

[providers.claude-cli]
kind             = "cli-oauth"
base_url         = ""
cli_binary_path  = "/opt/homebrew/bin/claude"
cli_timeout_secs = 180
models           = ["claude-sonnet-4-7", "claude-opus-4-7", "claude-haiku-4-5"]
```

Per-claw overlay (`~/.theyos/llm-profiles/openclaw.toml`):

```toml
[active]
provider = "claude-cli"
model    = "claude-opus-4-7"
```

Only the `[active]` section is needed in overlays — the `[providers.*]`
tables come from `default.toml`.

## Configuration env vars

| Var | Default | Purpose |
|---|---|---|
| `THEYOS_LLM_PROXY_PORT` | `18900` | Bind port. Must match `core_rs::claw_llm::DEFAULT_LLM_PROXY_PORT`. |
| `THEYOS_LLM_PROXY_BIND` | `127.0.0.1` | Bind address. Override with `0.0.0.0` ONLY for explicit testing — exposing the proxy to the LAN defeats the trust model. |
| `THEYOS_LLM_PROFILE_DIR` | `$HOME/.theyos/llm-profiles` | TOML profile directory. |
| `THEYOS_LLM_AUDIT_LOG` | `$HOME/.theyos/.run/llm-audit.log` | JSONL audit log path. Empty string disables logging. |
| `THEYOS_LLM_KEYSTORE` | `file` | Credential backend. `file` (default) uses 0600 files under `THEYOS_LLM_KEYSTORE_DIR`; `system` uses OS keystore (macOS Keychain / Linux Secret Service). Kernel keyring is wiped on service restart — avoid for production. |
| `THEYOS_LLM_KEYSTORE_DIR` | `$HOME/.theyos/keystore` | Root of the file keystore. Only consulted when `THEYOS_LLM_KEYSTORE=file`. |
| `THEYOS_LLM_PROXY_URL` (server-rs) | `http://127.0.0.1:18900` | Where `server-rs` reverse-proxy expects the daemon. Validated at startup: scheme MUST be `http` and host MUST be loopback (`127.0.0.1`, `::1`, `localhost`). Anything else falls back to default + logs an error. |
| `RUST_LOG` | `info,llm_proxy=info,tower_http=warn` | Standard `tracing-subscriber` filter. |

## Admin HTTP API

`server-rs` exposes the proxy's admin surface at `/api/v1/llm/*` behind
`AdminUser` session auth, then reverse-proxies each call to
`127.0.0.1:18900/admin/*` on loopback. The proxy daemon has no auth of
its own — the loopback bind is the trust boundary.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/llm/catalog` | Static catalog of all 22 providers (read-only). |
| GET | `/api/v1/llm/providers` | List configured providers, each annotated with `has_credential` + `in_use`. |
| POST | `/api/v1/llm/providers` | Create or update a provider config; optionally store a credential under `llm.api_key.<id>`. Hot-reloads the provider registry. |
| DELETE | `/api/v1/llm/providers/{id}` | Remove a provider; rejected with 400 if currently active. Best-effort credential delete. |
| POST | `/api/v1/llm/providers/{id}/test` | One-token live probe against the upstream. Returns `{ok, latency_ms, error?}`. |
| GET | `/api/v1/llm/active` | Current default + per-claw overlays. |
| PUT | `/api/v1/llm/active` | Set the global default. 422 if the provider isn't configured. |
| PUT | `/api/v1/llm/active/{claw_type}` | Install or update a per-claw overlay. |
| DELETE | `/api/v1/llm/active/{claw_type}` | Remove a per-claw overlay. |
| GET | `/api/v1/llm/audit?limit=N&before=ISO-8601` | Paginated audit log, newest-first. |

All mutations persist FIRST (atomic-rename to `default.toml` or
`<claw_type>.toml`), THEN swap the in-memory snapshot. If the disk
write fails, the in-memory state stays at the previous version and the
client sees an honest 5xx — runtime and disk never diverge.

Credential rotation: when `theyos-llm-proxy set-credential <account>`
runs against a host that already has the daemon up, it scans `/proc`
for the running PID and sends it a SIGHUP. The daemon catches SIGHUP
and rebuilds its provider registry from the current profile + keystore
— no restart needed.

## Audit log

Every successful AND failed chat request appends one JSON object to
`THEYOS_LLM_AUDIT_LOG`. Schema:

```json
{
  "ts":           "2026-05-18T01:20:17.003Z",
  "provider":    "anthropic",
  "claw_type":   "openclaw",
  "model":       "claude-opus-4-7",
  "stream":      true,
  "status":      "ok",
  "error_kind":  null,
  "latency_ms":  1247
}
```

Prompts and message contents are **never** written. Token counts surface
when the upstream returns usage (input_tokens / output_tokens).

Concurrent writes from multiple request handlers are serialised through
a `Mutex<File>` so lines never interleave.

## Service installation

### macOS (launchd)

Template at [`deploy/macos/com.theyos.llm-proxy.plist`](../deploy/macos/com.theyos.llm-proxy.plist).
Substitute `__USER__` and `__BIN_PATH__` then drop it under
`~/Library/LaunchAgents/`. `KeepAlive` is set to restart on crash but
allow a clean exit on first run (when no profile exists yet — the proxy
writes a stub and exits).

```sh
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.theyos.llm-proxy.plist
```

### NixOS (systemd)

Module at [`nix/modules/llm-proxy.nix`](../nix/modules/llm-proxy.nix).
Importable from `nix/module.nix` when `services.theyos.llm-proxy.enable`
is true. Hardened with:

- Dedicated `theyos-llm` system user.
- `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`.
- `RestrictAddressFamilies=[AF_UNIX, AF_INET, AF_INET6]`.
- `SystemCallFilter=[@system-service, ~@privileged, ~@resources]`.
- `ReadWritePaths=[/var/lib/theyos-llm, /var/log/theyos-llm]`.

State and logs live under `/var/lib/theyos-llm/` and
`/var/log/theyos-llm/` with mode `0750` owned by the service account.

## Test surface

| Suite | What it covers |
|---|---|
| `keystore_rs::*` (extracted Slice 0) | Generic OS-keystore primitives with file-fallback, used by `household-rs` + `llm-proxy-rs`. 11 tests. |
| `core_rs::claw_llm::*` | `provider=proxy` arms route to `DEFAULT_LLM_PROXY_PORT` with stamped `/v1/c/<claw>` URL. Per-claw URL stamp + placeholder API key tests. |
| `llm_proxy::profile::*` | Default profile load, first-run round-trip, per-claw overlay loading, malformed TOML reporting, unknown-provider validation. |
| `llm_proxy::audit::*` | JSONL roundtrip, concurrent-write line integrity, RFC3339 timestamp format, optional-field elision, leap-day handling. |
| `llm_proxy::translate::anthropic::*` | OpenAI↔Anthropic shape (system extraction, max_tokens default, stop string→array, tool function↔input_schema, tool_choice mapping, tool_use↔tool_calls, stop_reason mapping). 21 tests. |
| `llm_proxy::tests/openai_compat.rs` | Auth-header presence/absence, JSON passthrough, SSE passthrough, 5xx propagation. |
| `llm_proxy::tests/anthropic_api.rs` | Real HTTP via wiremock: POST to `/v1/messages`, headers, request-body translation, streaming text + tool_use re-emission, abrupt-cutoff recovery. |
| `llm_proxy::tests/claude_cli.rs` | Subprocess invocation via mock binary: argv shape, stdout passthrough, non-zero exit, missing binary, timeout enforcement, streaming, integration through proxy router. |
| `llm_proxy::tests/catalog.rs` | Unique ids, openclaw id alignment, base-URL well-formedness, model lists non-empty, credential hints match kind, every catalog entry instantiates a Provider, coding-plan toggle, /admin/catalog endpoint. |
| `llm_proxy::tests/e2e.rs` | Full pipeline: client → axum → mock upstream, default route + per-claw overlay route. |
| `llm_proxy::tests/audit.rs` | Audit JSONL written for OK + error paths, stream flag, disabled-logger no-op, multi-request order, claw_type round-trip. |

Total in `llm-proxy-rs` alone: **89 tests, 1 ignored doc test, 0 failures**
across 9 test files. Plus 209 tests in `household-rs` (no regressions
from the Slice 0 extraction) and 296 in `core-rs` (with the new
`provider=proxy` arms tested).

## Operating runbook

### Bootstrap a new host

1. Build: `cargo build --release -p llm-proxy-rs`.
2. Install:
   - macOS: copy binary to `/opt/homebrew/bin/theyos-llm-proxy`,
     install the launchd plist.
   - NixOS: enable the module in your host's nix config.
3. First boot will write a stub `default.toml` and exit cleanly. Edit
   the profile, then restart the service.
4. Tell each claw's `~/.theyos/llm-profile.env` to route through
   the proxy, then activate a provider via the admin HTTP API:
   ```sh
   # Claw side (per host user): route guest LLM calls to the proxy.
   printf 'THEYOS_LLM_PROVIDER=proxy\nTHEYOS_LLM_MODEL=any\n' \
     > ~/.theyos/llm-profile.env

   # Host side: pick the active provider/model.
   curl -sS -X PUT http://127.0.0.1:18900/admin/llm/active \
     -H 'content-type: application/json' \
     -d '{"provider":"ollama","model":"llama3.1"}'
   ```
5. Verify: `curl http://127.0.0.1:18900/health`.

### Add a cloud provider (e.g. Z.AI Coding Plan)

1. Store the API key in the host keystore. On macOS via the
   `security` CLI (or any keychain GUI):
   ```sh
   security add-generic-password -s com.soyeht.theyos -a llm.api_key.zai -w
   ```
2. Add to `default.toml`:
   ```toml
   [providers.zai]
   kind                = "openai-compat"
   base_url            = "https://api.z.ai/api/coding/paas/v4"
   credential_account  = "llm.api_key.zai"
   models              = ["glm-5.1", "glm-4.7"]
   ```
3. Activate via the admin HTTP API:
   ```sh
   curl -sS -X PUT http://127.0.0.1:18900/admin/llm/active \
     -H 'content-type: application/json' \
     -d '{"provider":"zai","model":"glm-5.1"}'
   ```
4. The daemon hot-reloads on SIGHUP (`theyos-llm-proxy set-credential`
   sends it automatically). A restart also works.
5. Verify: `curl -X POST http://127.0.0.1:18900/v1/chat/completions
   -d '{"model":"glm-5.1","messages":[{"role":"user","content":"hi"}]}'`.

### Inspect requests

```sh
tail -f $HOME/.theyos/.run/llm-audit.log | jq .
```

### Verified production PTY path

The full claw-side data path was verified end-to-end on devs
(`devs.tail295ab5.ts.net`) on 2026-05-18:

1. **Host proxy live as systemd unit:** `systemctl status theyos-llm-proxy`
   shows `active (running)`, listening on `127.0.0.1:18900`, File keystore
   at `$HOME/.theyos/keystore/`, profile `default.toml` active with `glm`.
2. **Claw spawned via admin API:** `POST /api/v1/instances {claw_type:
   "hermes-agent"}` produced a running Firecracker VM (`hermes-agent-hm`).
3. **fc-ssh pty opened the reverse tunnel and stamped the contract.**
   The proxy provider was selected via `~/.theyos/llm-profile.env`
   (`THEYOS_LLM_PROVIDER=proxy`, `THEYOS_LLM_MODEL=glm-4.6`). Running
   `fc-ssh pty hermes-agent-hm <session>` produced this banner on stdout
   from `claw_llm_bootstrap.sh` inside the guest:
   ```text
   [theyOS] LLM contract v1: provider proxy, guest 127.0.0.1:18900 ->
            upstream 127.0.0.1:18900, model glm-4.6
   ```
   confirming the env vars `THEYOS_LLM_OPENAI_BASE_URL`,
   `THEYOS_LLM_MODEL`, and the `-R 18900:127.0.0.1:18900` SSH forward all
   landed correctly via `LlmContract::render_pty_shell` +
   `LlmContract::ssh_reverse_forward`.
4. **Guest agent consumed the proxy.** Hermes Agent's TUI launched
   inside the VM with `glm-4.6 · Nous Research` as the active model —
   loaded by reading `THEYOS_LLM_OPENAI_BASE_URL` and reaching the
   proxy via the reverse tunnel. Listing models would have failed if
   either the tunnel or the contract was misconfigured.
5. **Earlier direct test (same session):** running `ssh -R 18900` into
   the same VM and `curl
   http://127.0.0.1:18900/v1/c/hermes-agent/chat/completions` returned a
   `PING` completion from the GLM upstream within ~9s, with the call
   recorded in `~/.theyos/.run/llm-audit.log` (`provider=glm`,
   `claw_type=hermes-agent`, `status=ok`).

To repeat this validation on any host with the proxy enabled:
```sh
# 1. host side
echo 'THEYOS_LLM_PROVIDER=proxy'    >  ~/.theyos/llm-profile.env
echo 'THEYOS_LLM_MODEL=glm-4.6'     >> ~/.theyos/llm-profile.env

# 2. spawn a claw via admin API or `soyeht` CLI

# 3. open a PTY: stdout banner must show provider=proxy + correct guest
#    port and model — that is the contract proof
sudo -u $(systemctl show -p User soyeht-admin-host --value) \
  fc-ssh pty <container_name> <session_name>
```

### All-claws matrix (2026-05-18)

The validation above was extended on the same day to cover every
working claw, not just the openclaw / hermes-agent pair. Each claw
type was spawned alone (1 vCPU / 2 GB / 5 GB to fit devs' 3-core
budget), probed via raw `ssh -R 127.0.0.1:18900:127.0.0.1:18900` (the
same forward `LlmContract::ssh_reverse_forward` emits), and asked to
curl `http://127.0.0.1:18900/v1/c/<claw_type>/chat/completions`.
Providers were alternated per claw (one ollama row, one GLM row,
repeating) so both upstreams are exercised across the full set.

Result tallies (35 claws — 8 supported + 27 verify-ok):

| Result | Count | What it means for the proxy |
|---|---|---|
| `ok` | 22 | Reverse tunnel landed, env contract stamped, completion came back |
| `INSTALL_TIMEOUT` | 12 | Claw image builder didn't finish in 5 min on devs (per-claw issue, **not** proxy) |
| `TERMINAL:failed` | 1 | `openclaw` upstream build broken (`tsdown` hangs at `node scripts/build-all.mjs`, both attempts) |

Provider split for the 22 successes — 13 against ollama, 9 against
GLM. Every claw that booted talked to the proxy successfully. The
first `rt-claw/glm` run failed `ok_no_completion` (env vars stamped
but completion never reached the proxy); a clean retry succeeded so
it's tallied as `ok` here — recorded for completeness because it's
the only transient case observed across 35 spawns.

Per-claw results:

| claw | provider | result |
|---|---|---|
| picoclaw | ollama | ok |
| zeroclaw | glm | ok |
| nanobot | ollama | ok |
| openclaw | glm | TERMINAL:failed (upstream `tsdown` hang) |
| nullclaw | ollama | ok |
| hermes-agent | glm | ok |
| ironclaw | ollama | ok |
| noclaw | glm | ok |
| angel-claw | ollama | ok |
| claw-empire | glm | ok |
| clawdroid | ollama | INSTALL_TIMEOUT |
| clawlet | glm | INSTALL_TIMEOUT |
| clawwork | ollama | ok |
| clawx | glm | INSTALL_TIMEOUT |
| dr-claw | ollama | ok |
| edgeclaw | glm | ok |
| epsiclaw | ollama | ok |
| geneclaw | glm | ok |
| hermitclaw | ollama | ok |
| kkclaw | glm | INSTALL_TIMEOUT |
| loki-claw | ollama | ok |
| microclaw | glm | INSTALL_TIMEOUT |
| myclaw | ollama | ok |
| n8n-claw | glm | INSTALL_TIMEOUT |
| nanoclaw | ollama | INSTALL_TIMEOUT |
| openclawbox | glm | INSTALL_TIMEOUT |
| rosclaw | ollama | INSTALL_TIMEOUT |
| rt-claw | glm | ok (1 transient retry) |
| safeclaw | ollama | ok |
| sharpclaw | glm | INSTALL_TIMEOUT |
| shibaclaw | ollama | ok |
| subzeroclaw | glm | ok |
| tinyagi | ollama | INSTALL_TIMEOUT |
| xsafeclaw | glm | ok |
| zeptoclaw | ollama | INSTALL_TIMEOUT |

The point of the matrix is **not** "every claw was tested against every
provider" — the claw side of the contract is provider-agnostic. The
matrix proves that *every claw that boots* can resolve the loopback URL
and reach the proxy, so adding a new claw to theyOS is a zero-work
change from the LLM proxy's perspective. Install-side failures
(`INSTALL_TIMEOUT`, openclaw's `tsdown` hang) are claw-specific
build/image issues, orthogonal to the LLM contract.

### Switch a single claw to a different provider

```sh
# openclaw now uses Claude Code subscription; everything else stays on ollama.
curl -sS -X PUT http://127.0.0.1:18900/admin/llm/active/openclaw \
  -H 'content-type: application/json' \
  -d '{"provider":"claude-cli","model":"claude-opus-4-7"}'

# Clear the overlay (openclaw falls back to the default):
# curl -sS -X DELETE http://127.0.0.1:18900/admin/llm/active/openclaw
```

## What's NOT in this v1

These are tracked but defer to follow-up slices:

- **OpenAI Codex OAuth** (`openai-codex` ChatGPT subscription) — requires
  OAuth client + token refresh infra. The `cli-oauth` pattern is in
  place; the OAuth dance and Codex transport need their own subgroup.
- **Gemini CLI** — straightforward subprocess but the `gemini` CLI's
  exact argv pattern wasn't verified live in the Slice 6 window.
- **GitHub Copilot** — OpenAI-compat against `api.githubcopilot.com`
  with a `gh auth token` credential source. Just a catalog entry +
  small credential-fetch helper.
- **Live reload** of profiles via admin API (Slice 5 part 2). Today the
  proxy reloads on process restart only.
- **Prometheus `/metrics`** — audit log covers per-request accounting;
  a Prometheus exporter on top would help fleet-level dashboards.
- **Frontend wiring to `/admin/catalog`** — the Models page
  (`admin/frontend/src/pages/ModelsPage.tsx`) still uses an in-file
  constant. Switching it to a `fetch('/api/v1/llm/catalog')` plus a
  Vite proxy entry is mechanical work.
- **server-rs admin endpoints** — the proxy's `/admin/*` endpoints are
  meant to be consumed by `server-rs` (the admin host) on behalf of the
  frontend. The pass-through in server-rs is unimplemented today.

## Pointers

- Catalog source of truth:
  [`admin/rust/llm-proxy-rs/src/catalog/providers.rs`](../admin/rust/llm-proxy-rs/src/catalog/providers.rs)
- Request translation (Anthropic example):
  [`admin/rust/llm-proxy-rs/src/translate/anthropic.rs`](../admin/rust/llm-proxy-rs/src/translate/anthropic.rs)
- The contract claws consume:
  [`docs/claw-llm-contract.md`](claw-llm-contract.md)
- Architecture memory:
  [`memory/project_llm_host_proxy_architecture.md`](../)
