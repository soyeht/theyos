# Local LLM providers for claws

This is the user-facing guide for choosing a local model runtime. The claw sees
one simple contract:

```text
provider + model + local URL + context window
```

The iPhone never talks to the model directly. theyOS opens the terminal, creates
the tunnel, and injects the contract into the claw.

## Switching Models

Write `~/.theyos/llm-profile.env` directly. The next claw terminal
picks up the new profile:

```bash
# Ollama with a larger context window.
cat > ~/.theyos/llm-profile.env <<'EOF'
THEYOS_LLM_PROVIDER=ollama
THEYOS_LLM_MODEL=qwen3:4b
THEYOS_LLM_CONTEXT_WINDOW=262144
EOF

# llama.cpp on a non-default port.
cat > ~/.theyos/llm-profile.env <<'EOF'
THEYOS_LLM_PROVIDER=llamacpp
THEYOS_LLM_MODEL=local64
THEYOS_LLM_HOST_PORT=18082
THEYOS_LLM_GUEST_PORT=18082
THEYOS_LLM_CONTEXT_WINDOW=65536
EOF

# MLX (macOS / Apple Silicon only).
cat > ~/.theyos/llm-profile.env <<'EOF'
THEYOS_LLM_PROVIDER=mlx
THEYOS_LLM_MODEL=mlx-community/Qwen3-4B-Instruct-2507-4bit
THEYOS_LLM_HOST_PORT=18080
THEYOS_LLM_GUEST_PORT=18080
THEYOS_LLM_CONTEXT_WINDOW=32768
EOF
```

For multi-provider switching without rewriting this file, use the
[Aurora proxy](llm-proxy.md) and set `THEYOS_LLM_PROVIDER=proxy`.

MLX is macOS/Apple Silicon only. On NixOS, use Ollama or llama.cpp.

## Ollama

Best default on Mac and Linux.

```bash
ollama serve
ollama pull qwen3.6:35b-a3b-coding-mxfp8

export THEYOS_LLM_PROVIDER=ollama
export THEYOS_LLM_MODEL=qwen3.6:35b-a3b-coding-mxfp8
export THEYOS_LLM_CONTEXT_WINDOW=262144
```

Inside the claw:

```text
THEYOS_LLM_BASE_URL=http://127.0.0.1:11434
THEYOS_LLM_OPENAI_BASE_URL=http://127.0.0.1:11434/v1
```

## llama.cpp

Good for GGUF models on Mac or Linux. Use a stable alias, usually `local`, so
claws do not need to know the GGUF filename.

Example Hugging Face model:

```text
unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF
```

Example launch:

```bash
llama-server \
  -m /models/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf \
  -a local \
  -c 65536 \
  --host 127.0.0.1 \
  --port 8080

export THEYOS_LLM_PROVIDER=llamacpp
export THEYOS_LLM_MODEL=local
export THEYOS_LLM_CONTEXT_WINDOW=65536
```

Inside the claw:

```text
THEYOS_LLM_BASE_URL=http://127.0.0.1:8080
THEYOS_LLM_OPENAI_BASE_URL=http://127.0.0.1:8080/v1
```

## MLX

Mac-only. Best fit for Apple Silicon.

Example Hugging Face models:

```text
mlx-community/Qwen3-4B-Instruct-2507-4bit
mlx-community/Mistral-7B-Instruct-v0.3-4bit
NexVeridian/Qwen3-Coder-30B-A3B-Instruct-4bit
```

Example launch:

```bash
mlx_lm.server --model mlx-community/Qwen3-4B-Instruct-2507-4bit

export THEYOS_LLM_PROVIDER=mlx
export THEYOS_LLM_MODEL=mlx-community/Qwen3-4B-Instruct-2507-4bit
export THEYOS_LLM_CONTEXT_WINDOW=32768
```

Inside the claw:

```text
THEYOS_LLM_BASE_URL=http://127.0.0.1:8080
THEYOS_LLM_OPENAI_BASE_URL=http://127.0.0.1:8080/v1
```

## Context Window Rule

Always set `THEYOS_LLM_CONTEXT_WINDOW` to the real runtime context:

- Ollama: check `ollama show <model>`.
- llama.cpp: use the same value passed to `llama-server -c`.
- MLX: use the model's documented max context, or a lower safe value.

theyOS will try to detect context automatically for Ollama and llama.cpp, but
an explicit env value wins. This keeps claws from assuming a larger context than
the runtime can actually serve.

Hermes can reject very small contexts. In the Mac tests, `qwen3:1.7b` was
rejected because it exposed `40960`, while `qwen3:4b` and `llama.cpp -c 65536`
worked.
