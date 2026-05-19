# Claw LLM contract

Status: v1.

This contract lets any claw use a local or host-provided LLM without requiring
the iOS client to know the claw's model configuration format. iOS still opens a
terminal WebSocket. The shared Rust implementation lives in
`core-rs::claw_llm`; `fc-ssh` (Linux/Firecracker) and `theyos-ssh` (macOS VZ)
both render that same contract before the claw shell starts.

## Transport

For local LLM deployments, `fc-ssh pty` and `theyos-ssh pty` create a reverse
SSH tunnel by default:

```text
guest 127.0.0.1:<guest-port> -> host 127.0.0.1:<provider-port>
```

The guest uses loopback, so claws do not need direct access to the host network.
This works even when the Firecracker guest network blocks host loopback.

## Environment

Every PTY receives these provider-neutral variables:

- `THEYOS_LLM_CONTRACT_VERSION=1`
- `THEYOS_CLAW_TYPE`: claw id, for example `openclaw`. Linux reads this from
  `instance.env`; macOS VZ infers it from the instance/container name.
- `THEYOS_LLM_PROVIDER`: provider id. Supported local presets: `ollama`,
  `llamacpp`, and `mlx`. Aliases like `llama.cpp`, `llama-cpp`, and `mlx-lm`
  are normalized.
- `THEYOS_LLM_MODEL`: selected model. Default depends on provider.
- `THEYOS_LLM_BASE_URL`: native provider base URL. For Ollama, no `/v1`.
- `THEYOS_LLM_NATIVE_BASE_URL`: alias for the native provider URL.
- `THEYOS_LLM_OPENAI_BASE_URL`: OpenAI-compatible URL for clients that require
  `/v1`.
- `THEYOS_LLM_API_KEY`: placeholder or real credential for clients that require
  an API key field.
- `THEYOS_LLM_CONTEXT_WINDOW`: context window promised to the claw.
- `THEYOS_LLM_CONTEXT_SOURCE`: `env`, `runtime`, `model-profile`, or
  `safe-fallback`.
- `THEYOS_LLM_HOST_ADDR`: upstream host/address used by the reverse SSH tunnel.
  Default: `127.0.0.1`.
- `THEYOS_LLM_HOST_PORT`: port on the host. Defaults: Ollama `11434`,
  llama.cpp/MLX `8080`.
- `THEYOS_LLM_GUEST_PORT`: port exposed inside the guest. Default: host port.

The bootstrap also exports compatibility variables for common clients:

- Ollama: `OLLAMA_HOST`, `OLLAMA_BASE_URL`, `OLLAMA_API_KEY`.
- OpenAI-compatible SDKs: `OPENAI_BASE_URL`, `OPENAI_API_BASE`,
  `OPENAI_API_KEY`.
- Existing theyOS Ollama knobs: `THEYOS_OLLAMA_HOST_ADDR`,
  `THEYOS_OLLAMA_HOST_PORT`, `THEYOS_OLLAMA_GUEST_PORT`,
  `THEYOS_OLLAMA_MODEL`, `THEYOS_OLLAMA_API_KEY`.

New claws should prefer `THEYOS_LLM_*`. The aliases exist only to keep existing
tools working.

## Host controls

The host can override the contract with:

- `THEYOS_LLM_SSH_TUNNEL=0`: disable the reverse SSH tunnel.
- `THEYOS_LLM_HOST_ADDR`: host/address behind the SSH reverse tunnel. Use this
  when the model server is not bound to the theyOS host loopback.
- `THEYOS_LLM_HOST_PORT`: host-side local LLM port.
- `THEYOS_LLM_GUEST_PORT`: guest-side loopback port.
- `THEYOS_LLM_PROVIDER`: provider id, currently `ollama` by default.
- `THEYOS_LLM_MODEL`: model name to select.
- `THEYOS_LLM_CONTEXT_WINDOW`: override model context. This should match the
  runtime's real context (`ollama show`, `llama-server -c`, or the MLX model).
- `THEYOS_LLM_CONTEXT_AUTO_DETECT=0`: disable runtime context detection.
- `THEYOS_LLM_PROFILE_PATH`: optional `KEY=VALUE` profile file. If unset,
  theyOS reads `$THEYOS_DIR/.run/llm-profile.env`, then
  `$HOME/.theyos/llm-profile.env` when present. Process env vars still win over
  the profile file.
- `THEYOS_LLM_BASE_URL`: explicit native provider URL inside the guest.
- `THEYOS_LLM_OPENAI_BASE_URL`: explicit OpenAI-compatible URL.
- `THEYOS_LLM_API_KEY`: API key or placeholder.
- `THEYOS_HERMES_CHAT_MODE`: built-in Hermes launcher mode. macOS and
  Linux/Firecracker default: `chat`.
- `THEYOS_OPENCLAW_CHAT_MODE`: built-in OpenClaw launcher mode. macOS default:
  `local`; Linux/Firecracker default: `gateway`.
- `THEYOS_OPENCLAW_PROVIDER_KEY`: OpenClaw config path for the provider entry.
  Default: `models.providers.$THEYOS_LLM_PROVIDER`.
- `THEYOS_OPENCLAW_MODEL_REF`: OpenClaw default model reference. Default:
  `$THEYOS_LLM_PROVIDER/$THEYOS_LLM_MODEL`.
- `THEYOS_AUTO_START_CLAW_CHAT=0`: skip adapter chat startup and open a normal
  shell.

`THEYOS_OLLAMA_*` remains supported as a backward-compatible alias.

## Local Provider Presets

| Provider | Host port | Default model | API exposed to claws |
| --- | ---: | --- | --- |
| `ollama` | `11434` | `llama3.1` | Native Ollama plus OpenAI-compatible `/v1` |
| `llamacpp` | `8080` | `local` | OpenAI-compatible `/v1` |
| `mlx` | `8080` | `mlx-community/Qwen3-4B-Instruct-2507-4bit` | OpenAI-like `/v1` |

Context window priority:

1. `THEYOS_LLM_CONTEXT_WINDOW`
2. runtime detection (`/api/show` for Ollama, `/props` for llama.cpp)
3. built-in model profile for known examples
4. safe fallback `8192`

Write the profile file directly — the claw-side bootstrap reads it as
plain `KEY=VALUE` env:

```bash
# Local ollama with custom model + context.
cat > ~/.theyos/llm-profile.env <<'EOF'
THEYOS_LLM_PROVIDER=ollama
THEYOS_LLM_MODEL=qwen3:4b
THEYOS_LLM_CONTEXT_WINDOW=262144
EOF

# Local llama.cpp on a non-default port.
cat > ~/.theyos/llm-profile.env <<'EOF'
THEYOS_LLM_PROVIDER=llamacpp
THEYOS_LLM_MODEL=local64
THEYOS_LLM_HOST_PORT=18082
THEYOS_LLM_GUEST_PORT=18082
THEYOS_LLM_CONTEXT_WINDOW=65536
EOF

# Local MLX with a 4-bit Qwen3 model.
cat > ~/.theyos/llm-profile.env <<'EOF'
THEYOS_LLM_PROVIDER=mlx
THEYOS_LLM_MODEL=mlx-community/Qwen3-4B-Instruct-2507-4bit
THEYOS_LLM_HOST_PORT=18080
THEYOS_LLM_GUEST_PORT=18080
THEYOS_LLM_CONTEXT_WINDOW=32768
EOF
```

For a host with the LLM proxy installed (Aurora v1+), set
`THEYOS_LLM_PROVIDER=proxy` and let the proxy's `[active]` profile
pick the upstream — the admin API
(`PUT /admin/llm/active`, see [`docs/llm-proxy.md`](llm-proxy.md))
swaps providers without rewriting this file.

The next claw PTY uses the updated profile; the iOS client does not need to
change.

For llama.cpp, run the server with a stable alias so every claw can use the same
friendly model id:

```bash
llama-server -m /models/model.gguf -a local -c 32768 --host 127.0.0.1 --port 8080
export THEYOS_LLM_PROVIDER=llamacpp
export THEYOS_LLM_MODEL=local
export THEYOS_LLM_CONTEXT_WINDOW=32768
```

For MLX on macOS:

```bash
mlx_lm.server --model mlx-community/Qwen3-4B-Instruct-2507-4bit
export THEYOS_LLM_PROVIDER=mlx
export THEYOS_LLM_MODEL=mlx-community/Qwen3-4B-Instruct-2507-4bit
export THEYOS_LLM_CONTEXT_WINDOW=32768
```

## Adapter protocol

A claw can consume the environment directly. If it needs a config file or a
specific TUI command, it should ship an adapter executable in one of these
locations:

- `/opt/claws/<claw-type>/theyos-llm-adapter`
- `/usr/local/lib/theyos/llm-adapters/<claw-type>`
- `/usr/local/bin/theyos-<claw-type>-llm-adapter`

The host can also point to an adapter with `THEYOS_LLM_ADAPTER_PATH`.

The adapter is invoked with one argument:

- `configure`: idempotently write claw config from the contract environment.
  This command must be non-interactive and safe to run on every PTY attach.
- `chat`: start the claw's interactive chat or TUI. When it exits, theyOS falls
  back to the normal shell.

Adapters must not print, log, or persist secret values except in the claw's own
expected credential store. Prefer placeholders for local providers when the claw
accepts them.

Minimal adapter shape:

```sh
#!/bin/sh
set -eu

case "${1:-}" in
  configure)
    # Write config using THEYOS_LLM_BASE_URL, THEYOS_LLM_OPENAI_BASE_URL,
    # THEYOS_LLM_MODEL, and THEYOS_LLM_API_KEY.
    ;;
  chat)
    exec my-claw-chat
    ;;
  *)
    exit 64
    ;;
esac
```

## Built-in adapters

The shared bootstrap currently includes built-in adapters for:

- `hermes-agent`: writes Hermes `model.provider`, `model.base_url`,
  `model.model`, `model.default`, and `model.api_key`. macOS VZ starts
  `hermes chat --provider custom -m "$THEYOS_LLM_MODEL"`; Linux/Firecracker
  keeps the existing Hermes TUI startup path, `hermes --tui`.
- `openclaw`: writes a provider entry using the native provider URL for Ollama
  and the OpenAI-compatible URL for llama.cpp/MLX, sets
  `agents.defaults.model.primary` to `THEYOS_OPENCLAW_MODEL_REF`, and then
  starts the requested OpenClaw mode. If the installed OpenClaw supports
  `openclaw tui --local`, the bootstrap uses it. Otherwise it starts the
  loopback OpenClaw gateway with token auth and connects with
  `openclaw tui --url "$OPENCLAW_GATEWAY_URL" --token "$OPENCLAW_GATEWAY_TOKEN"`.

These built-ins are the first contract consumers. Future claws should generally
use packaged adapters so support can be updated with the claw image.
