export THEYOS_LLM_API_KEY="${THEYOS_LLM_API_KEY:-${THEYOS_OLLAMA_API_KEY:-ollama}}";
export THEYOS_OLLAMA_GUEST_PORT="${THEYOS_OLLAMA_GUEST_PORT:-$THEYOS_LLM_GUEST_PORT}";
export THEYOS_OLLAMA_HOST_ADDR="${THEYOS_OLLAMA_HOST_ADDR:-$THEYOS_LLM_HOST_ADDR}";
export THEYOS_OLLAMA_HOST_PORT="${THEYOS_OLLAMA_HOST_PORT:-$THEYOS_LLM_HOST_PORT}";
export THEYOS_OLLAMA_MODEL="${THEYOS_OLLAMA_MODEL:-$THEYOS_LLM_MODEL}";
export THEYOS_OLLAMA_API_KEY="${THEYOS_OLLAMA_API_KEY:-$THEYOS_LLM_API_KEY}";
export OLLAMA_HOST="${OLLAMA_HOST:-$THEYOS_LLM_BASE_URL}";
export OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-$THEYOS_LLM_BASE_URL}";
export OLLAMA_API_KEY="${OLLAMA_API_KEY:-ollama-local}";
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-$THEYOS_LLM_OPENAI_BASE_URL}";
export OPENAI_API_BASE="${OPENAI_API_BASE:-$OPENAI_BASE_URL}";
export OPENAI_API_KEY="${OPENAI_API_KEY:-$THEYOS_LLM_API_KEY}";
export NODE_NO_WARNINGS="${NODE_NO_WARNINGS:-1}";
export HERMES_HOME="${HERMES_HOME:-/opt/data}";
export HERMES_MODEL="${HERMES_MODEL:-$THEYOS_LLM_MODEL}";
export OPENCLAW_MODEL="${OPENCLAW_MODEL:-$THEYOS_LLM_MODEL}";
export OPENCLAW_GATEWAY_TOKEN="${OPENCLAW_GATEWAY_TOKEN:-${THEYOS_OPENCLAW_GATEWAY_TOKEN:-theyos-local}}";

theyos_have() {
  command -v "$1" >/dev/null 2>&1;
}

theyos_print_llm_banner() {
  printf '\033[2m[theyOS] LLM contract v%s: provider %s, guest 127.0.0.1:%s -> upstream %s:%s, model %s\033[0m\n' "$THEYOS_LLM_CONTRACT_VERSION" "$THEYOS_LLM_PROVIDER" "$THEYOS_LLM_GUEST_PORT" "$THEYOS_LLM_HOST_ADDR" "$THEYOS_LLM_HOST_PORT" "$THEYOS_LLM_MODEL";
}

theyos_run_external_claw_adapter() {
  action="$1";
  [ -n "$THEYOS_CLAW_TYPE" ] || return 127;
  case "$THEYOS_CLAW_TYPE" in
    *[!A-Za-z0-9_-]*) return 127 ;;
  esac;
  if [ -n "${THEYOS_LLM_ADAPTER_PATH:-}" ] && [ -x "$THEYOS_LLM_ADAPTER_PATH" ]; then
    "$THEYOS_LLM_ADAPTER_PATH" "$action";
    return $?;
  fi;
  for adapter in \
    "/usr/local/lib/theyos/llm-adapters/$THEYOS_CLAW_TYPE" \
    "/opt/claws/$THEYOS_CLAW_TYPE/theyos-llm-adapter" \
    "/usr/local/bin/theyos-$THEYOS_CLAW_TYPE-llm-adapter"; do
    if [ -x "$adapter" ]; then
      "$adapter" "$action";
      return $?;
    fi;
  done;
  return 127;
}

theyos_configure_hermes_llm() {
  theyos_have hermes || return 0;
  mkdir -p "$HERMES_HOME";
  hermes config set model.provider custom >/dev/null 2>&1 || true;
  hermes config set model.base_url "$THEYOS_LLM_OPENAI_BASE_URL" >/dev/null 2>&1 || true;
  hermes config set model.model "$THEYOS_LLM_MODEL" >/dev/null 2>&1 || true;
  hermes config set model.default "$THEYOS_LLM_MODEL" >/dev/null 2>&1 || true;
  hermes config set model.api_key "$THEYOS_LLM_API_KEY" >/dev/null 2>&1 || true;
  hermes config set model.api_mode chat_completions >/dev/null 2>&1 || true;
}

theyos_configure_openclaw_llm() {
  theyos_have openclaw || return 0;
  if [ -n "${THEYOS_OPENCLAW_PROVIDER_JSON:-}" ]; then
    openclaw config set models.mode merge >/dev/null 2>&1 || true;
    theyos_openclaw_config_set_json "${THEYOS_OPENCLAW_PROVIDER_KEY:-models.providers.$THEYOS_LLM_PROVIDER}" "$THEYOS_OPENCLAW_PROVIDER_JSON";
  fi;
  model_ref="${THEYOS_OPENCLAW_MODEL_REF:-$THEYOS_LLM_PROVIDER/$THEYOS_LLM_MODEL}";
  openclaw config set agents.defaults.model.primary "$model_ref" >/dev/null 2>&1 || true;
}

theyos_openclaw_config_set_json() {
  key="$1";
  value="$2";
  if openclaw config set --help 2>/dev/null | grep -q -- "--json"; then
    openclaw config set "$key" "$value" --json >/dev/null 2>&1 || true;
  else
    openclaw config set "$key" "$value" --strict-json >/dev/null 2>&1 || true;
  fi;
}

theyos_start_openclaw_gateway() {
  gateway_url="${OPENCLAW_GATEWAY_URL:-ws://127.0.0.1:18789}";
  gateway_log="${OPENCLAW_GATEWAY_LOG:-/tmp/theyos-openclaw-gateway.log}";
  export OPENCLAW_GATEWAY_URL="$gateway_url";
  if theyos_openclaw_gateway_port_open && theyos_openclaw_gateway_health >/dev/null 2>&1; then
    return 0;
  fi;
  if ! theyos_openclaw_gateway_port_open; then
    : >"$gateway_log" 2>/dev/null || true;
    (openclaw gateway --allow-unconfigured --auth token --token "$OPENCLAW_GATEWAY_TOKEN" --bind loopback --port 18789 run >"$gateway_log" 2>&1 &);
  fi;
  i=0;
  while [ "$i" -lt 60 ]; do
    if theyos_openclaw_gateway_port_open && theyos_openclaw_gateway_health >/dev/null 2>&1; then
      return 0;
    fi;
    if [ -f "$gateway_log" ] && grep -q "\[gateway\] ready" "$gateway_log" 2>/dev/null; then
      return 0;
    fi;
    i=$((i + 1));
    sleep 1;
  done;
  return 0;
}

theyos_openclaw_gateway_port_open() {
  if theyos_have nc; then
    nc -z 127.0.0.1 18789 >/dev/null 2>&1;
    return $?;
  fi;
  if theyos_have bash; then
    bash -c ':</dev/tcp/127.0.0.1/18789' >/dev/null 2>&1;
    return $?;
  fi;
  return 1;
}

theyos_openclaw_gateway_health() {
  health_timeout="${THEYOS_OPENCLAW_HEALTH_TIMEOUT_SEC:-3}";
  if theyos_have timeout; then
    if timeout --help 2>/dev/null | grep -q -- "--kill-after"; then
      timeout --kill-after=1s "$health_timeout" openclaw gateway health --url "$gateway_url" --token "$OPENCLAW_GATEWAY_TOKEN";
    else
      timeout "$health_timeout" openclaw gateway health --url "$gateway_url" --token "$OPENCLAW_GATEWAY_TOKEN";
    fi;
    return $?;
  fi;
  openclaw gateway health --url "$gateway_url" --token "$OPENCLAW_GATEWAY_TOKEN" &
  health_pid="$!";
  i=0;
  while [ "$i" -lt "$health_timeout" ]; do
    if ! kill -0 "$health_pid" >/dev/null 2>&1; then
      wait "$health_pid";
      return $?;
    fi;
    i=$((i + 1));
    sleep 1;
  done;
  kill "$health_pid" >/dev/null 2>&1 || true;
  sleep 1;
  kill -KILL "$health_pid" >/dev/null 2>&1 || true;
  wait "$health_pid" >/dev/null 2>&1 || true;
  return 124;
}

theyos_openclaw_tui_supports_local() {
  openclaw tui --help 2>/dev/null | grep -q -- "--local";
}

theyos_openclaw_tui_local() {
  if theyos_openclaw_tui_supports_local; then
    openclaw tui --local --timeout-ms "${THEYOS_OPENCLAW_TIMEOUT_MS:-180000}" || true
    return 0;
  fi;
  theyos_start_openclaw_gateway || true;
  openclaw tui --url "${OPENCLAW_GATEWAY_URL:-ws://127.0.0.1:18789}" --token "$OPENCLAW_GATEWAY_TOKEN" --timeout-ms "${THEYOS_OPENCLAW_TIMEOUT_MS:-180000}" || true
}

theyos_configure_builtin_claw_llm() {
  case "$THEYOS_CLAW_TYPE" in
    hermes-agent) theyos_configure_hermes_llm ;;
    openclaw) theyos_configure_openclaw_llm ;;
  esac;
}

theyos_configure_claw_llm() {
  theyos_run_external_claw_adapter configure;
  adapter_status=$?;
  if [ "$adapter_status" -eq 127 ]; then
    theyos_configure_builtin_claw_llm;
  fi;
  return 0;
}

theyos_start_builtin_claw_chat() {
  case "$THEYOS_CLAW_TYPE" in
    hermes-agent)
      if theyos_have hermes; then
        case "${THEYOS_HERMES_CHAT_MODE:-chat}" in
          tui)
            if hermes --help 2>/dev/null | grep -q -- "--tui"; then
              hermes --tui || hermes chat -m "$THEYOS_LLM_MODEL" || hermes || true
            else
              hermes chat -m "$THEYOS_LLM_MODEL" || hermes || true
            fi
            ;;
          *) hermes chat -m "$THEYOS_LLM_MODEL" || hermes || true ;;
        esac;
      elif theyos_have hermes-agent; then
        hermes-agent || true;
      fi
      ;;
    openclaw)
      if theyos_have openclaw; then
        case "${THEYOS_OPENCLAW_CHAT_MODE:-local}" in
          gateway)
            theyos_start_openclaw_gateway || true;
            openclaw tui --url "${OPENCLAW_GATEWAY_URL:-ws://127.0.0.1:18789}" --token "$OPENCLAW_GATEWAY_TOKEN" --timeout-ms "${THEYOS_OPENCLAW_TIMEOUT_MS:-180000}" || true
            ;;
          *)
            theyos_openclaw_tui_local
            ;;
        esac;
      fi
      ;;
  esac;
}

theyos_start_claw_chat() {
  [ -n "${THEYOS_CLAW_TYPE:-}" ] || return 0;
  case "${THEYOS_AUTO_START_CLAW_CHAT:-1}" in
    0|false|FALSE|no|NO|off|OFF) return 0 ;;
  esac;
  theyos_configure_claw_llm;
  theyos_print_llm_banner;
  theyos_run_external_claw_adapter chat;
  adapter_status=$?;
  if [ "$adapter_status" -eq 127 ]; then
    theyos_start_builtin_claw_chat;
  fi;
  return 0;
}

theyos_start_claw_chat;
