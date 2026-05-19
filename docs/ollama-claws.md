# Ollama-backed claws

This is the Ollama deployment guide for the general [claw LLM
contract](claw-llm-contract.md). That contract is the canonical reference for
the environment variables, reverse SSH tunnel, and adapter protocol.
For MLX and llama.cpp, see [local LLM providers](local-llm-providers.md).

## Defaults

- Provider: `THEYOS_LLM_PROVIDER=ollama`
- Native URL inside the claw: `THEYOS_LLM_BASE_URL=http://127.0.0.1:11434`
- OpenAI-compatible URL: `THEYOS_LLM_OPENAI_BASE_URL=http://127.0.0.1:11434/v1`
- Default model: `THEYOS_LLM_MODEL=llama3.1`
- Context window: detected from Ollama when possible, otherwise set
  `THEYOS_LLM_CONTEXT_WINDOW` explicitly.
- Host endpoint behind the SSH tunnel: `THEYOS_LLM_HOST_ADDR=127.0.0.1`,
  `THEYOS_LLM_HOST_PORT=11434`

The old `THEYOS_OLLAMA_*` names still work as backward-compatible aliases, but
new claws should read `THEYOS_LLM_*`.

## Host prerequisites

Start Ollama on the host and make sure the selected model exists:

```bash
ollama serve
ollama pull llama3.1
```

For a different model:

```bash
export THEYOS_LLM_MODEL=qwen3.6:35b-a3b-coding-mxfp8
export THEYOS_LLM_CONTEXT_WINDOW=262144
```

Use `THEYOS_LLM_HOST_ADDR`, `THEYOS_LLM_HOST_PORT`, and
`THEYOS_LLM_GUEST_PORT` when Ollama is not on the default host loopback port.
Set `THEYOS_LLM_SSH_TUNNEL=0` only when the claw can reach the model server
directly.

## Built-in consumers

Hermes receives the OpenAI-compatible Ollama URL and model in its config. On
macOS VZ, the built-in launcher starts:

```bash
hermes chat --provider custom -m "$THEYOS_LLM_MODEL"
```

OpenClaw receives an `ollama` provider entry with the native Ollama URL and
default model reference `ollama/$THEYOS_LLM_MODEL`. The general contract exposes
that as `THEYOS_OPENCLAW_MODEL_REF`, so other providers do not need an
Ollama-specific prefix. When the installed OpenClaw supports local TUI mode, the
built-in launcher starts:

```bash
openclaw tui --local
```

Otherwise, including current Linux/Firecracker OpenClaw builds, the bootstrap
starts a loopback gateway with token auth and connects the TUI with:

```bash
openclaw tui --url "$OPENCLAW_GATEWAY_URL" --token "$OPENCLAW_GATEWAY_TOKEN"
```

## OpenClaw metadata

For large local models, these optional knobs only affect the generated OpenClaw
provider metadata:

```bash
export THEYOS_LLM_CONTEXT_WINDOW=32768
export THEYOS_LLM_MAX_TOKENS=4096
```

Existing Hermes/OpenClaw instances can be reused. Delete and recreate them only
if their installed CLI is stale or missing.
