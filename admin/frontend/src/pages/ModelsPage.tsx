import { useMemo, useState } from "react";
import type { FormEvent } from "react";

// Test/preview page for the Models UX. Backend is intentionally mocked —
// this is the surface we iterate on before `theyos-llm-proxy` and the
// catalog API land. Once those exist, the only change here is swapping
// the in-memory store for `api.*` calls; the render shape stays.

type ModelKind = "local" | "cloud";

type LocalProviderId = "ollama" | "llamacpp" | "mlx";

// Provider ids match openclaw/openclaw's bundled provider plugins so any
// provider chosen here works inside the claw without translation.
// See: github.com/openclaw/openclaw docs/concepts/model-providers.md
type CloudProviderId =
  | "openai"
  | "anthropic"
  | "google"
  | "deepseek"
  | "zai"          // GLM (Z.AI)
  | "moonshot"     // Kimi (regular API + Kimi Coding via Anthropic-compat)
  | "qwen"         // Alibaba (Qwen Cloud / DashScope / Coding Plan)
  | "minimax"      // includes minimax-portal coding plan
  | "xai"          // Grok
  | "volcengine"   // Doubao (China region)
  | "byteplus"     // BytePlus ARK (international)
  | "stepfun"
  | "cerebras"
  | "groq"
  | "mistral"
  | "openrouter"
  | "vercel-ai-gateway"
  | "kilocode"
  | "github-copilot"
  | "huggingface"
  | "nvidia"
  | "together"
  | "qianfan"      // Baidu
  | "opencode";    // opencode.ai Zen

type ProviderId = LocalProviderId | CloudProviderId;

type Capability =
  | "code"
  | "chat"
  | "writing"
  | "vision"
  | "reasoning"
  | "tools"
  | "long-context"
  | "agentic";

type Compatibility = "fits-well" | "should-fit" | "tight" | "wont-fit" | "untested";

type ConnectionState = "ok" | "no-credential" | "invalid-key" | "untested";

type InstallStatus = "not_installed" | "installing" | "ready" | "failed";

type SpeedClass = "fast" | "ok" | "slow" | "unmeasured";

type BillingMode = "api" | "plan";

type LocalModel = {
  kind: "local";
  id: string;
  display_name: string;
  technical_id: string;
  provider: LocalProviderId;
  tagline: string;
  quality: 1 | 2 | 3 | 4 | 5;
  parameters_b: number;
  parameters_active_b?: number; // MoE active count
  quantization: string;
  context_tokens: number;
  capabilities: ReadonlyArray<Capability>;
  download_size_gb: number;
  min_ram_gb: number;
  released?: string; // YYYY-MM
  compatibility: Compatibility;
  install: InstallStatus;
  measured_tokps?: number;
  speed_class: SpeedClass;
};

type CodingPlan = {
  name: string;
  url?: string;
  // Free-form note for caps/tiers (no prices — those change too often and
  // belong on the provider's signup page).
  note?: string;
};

type CloudModel = {
  kind: "cloud";
  id: string;
  display_name: string;
  technical_id: string;
  provider: CloudProviderId;
  tagline: string;
  quality: 1 | 2 | 3 | 4 | 5;
  context_tokens: number;
  capabilities: ReadonlyArray<Capability>;
  knowledge_cutoff?: string; // YYYY-MM
  plan_available?: CodingPlan;
  connection: ConnectionState;
  active_billing?: BillingMode;
};

type Model = LocalModel | CloudModel;

// ── Mock host fingerprint ───────────────────────────────────────────────────
const MOCK_HOST = {
  chip_family: "apple-silicon" as const,
  total_ram_gb: 64,
  available_ram_gb: 42,
};

const PROVIDER_LABEL: Record<ProviderId, string> = {
  ollama: "Ollama",
  llamacpp: "llama.cpp",
  mlx: "MLX",
  openai: "OpenAI",
  anthropic: "Anthropic",
  google: "Google",
  deepseek: "DeepSeek",
  zai: "Z.AI (GLM)",
  moonshot: "Moonshot (Kimi)",
  qwen: "Alibaba (Qwen)",
  minimax: "MiniMax",
  xai: "xAI (Grok)",
  volcengine: "Volcano Engine (Doubao)",
  byteplus: "BytePlus ARK",
  stepfun: "StepFun",
  cerebras: "Cerebras",
  groq: "Groq",
  mistral: "Mistral",
  openrouter: "OpenRouter",
  "vercel-ai-gateway": "Vercel AI Gateway",
  kilocode: "Kilo Gateway",
  "github-copilot": "GitHub Copilot",
  huggingface: "Hugging Face",
  nvidia: "NVIDIA NIM",
  together: "Together",
  qianfan: "Baidu Qianfan",
  opencode: "OpenCode (Zen)",
};

// Providers that publish a coding-plan subscription (per openclaw docs).
// Used by AddProviderForm to decide whether to show the billing-mode toggle.
const PROVIDERS_WITH_PLAN: ReadonlySet<CloudProviderId> = new Set<CloudProviderId>([
  "anthropic",    // Claude Pro/Max (Claude Code) via Claude CLI OAuth
  "openai",       // Codex via ChatGPT subscription OAuth
  "google",       // Gemini CLI OAuth
  "zai",          // Z.AI Coding Plan (API key)
  "moonshot",     // Kimi Code via Kimi Membership (API key)
  "qwen",         // Alibaba AI Coding Plan (API key)
  "minimax",      // MiniMax Coding Plan (API key or OAuth)
  "volcengine",   // Volcano Engine Coding (API key)
  "byteplus",     // BytePlus Coding (API key)
  "stepfun",      // StepFun coding plan (API key)
  "github-copilot", // GitHub OAuth
  "opencode",     // OpenCode Zen (API key)
]);

// How each provider's coding plan is actually authenticated. Anthropic Claude
// Code, OpenAI Codex, and Google Gemini CLI use OAuth bound to a CLI tool on
// the *host* — there is no token to paste in the browser. Everything else
// hands you an API key on a dashboard.
type PlanAuthKind = "api-key" | "cli-oauth";

const PLAN_AUTH_KIND: Record<CloudProviderId, PlanAuthKind> = {
  // OAuth via CLI (no paste)
  anthropic: "cli-oauth",
  openai: "cli-oauth",
  google: "cli-oauth",
  "github-copilot": "cli-oauth",
  // API key (paste a token)
  zai: "api-key",
  moonshot: "api-key",
  qwen: "api-key",
  minimax: "api-key",
  volcengine: "api-key",
  byteplus: "api-key",
  stepfun: "api-key",
  opencode: "api-key",
  // The rest don't have plans, but the map needs entries so TS is happy.
  // Default kind is irrelevant since the plan path is hidden for these.
  deepseek: "api-key",
  xai: "api-key",
  cerebras: "api-key",
  groq: "api-key",
  mistral: "api-key",
  openrouter: "api-key",
  "vercel-ai-gateway": "api-key",
  kilocode: "api-key",
  huggingface: "api-key",
  nvidia: "api-key",
  together: "api-key",
  qianfan: "api-key",
};

// Per-provider plan setup instructions when the auth kind is cli-oauth.
// These match openclaw's documented onboarding flows for each subscription.
const CLI_OAUTH_INSTRUCTIONS: Partial<Record<CloudProviderId, {
  cli: string;
  install: string;
  login: string;
  note?: string;
}>> = {
  anthropic: {
    cli: "Claude CLI",
    install: "brew install claude  (or: npm i -g @anthropic-ai/claude-code)",
    login: "claude login",
    note: "install on the theyOS host (the machine running soyeht), NOT inside the claw. the claw stays untrusted — your subscription token never crosses into it. theyOS bridges the claw's loopback to the host's Claude CLI.",
  },
  openai: {
    cli: "OpenAI Codex (ChatGPT OAuth)",
    install: "no install needed — uses the openclaw onboarding flow",
    login: "openclaw onboard --auth-choice openai-codex  (run on the theyOS host)",
    note: "the OAuth dance runs on the theyOS host (the machine running soyeht). the claw never sees the ChatGPT token.",
  },
  google: {
    cli: "Gemini CLI",
    install: "brew install gemini-cli  (or: npm i -g @google/gemini-cli)",
    login: "openclaw models auth login --provider google-gemini-cli  (run on the theyOS host)",
    note: "install on the theyOS host, not the claw. unofficial Google integration — consider a secondary Google account.",
  },
  "github-copilot": {
    cli: "GitHub CLI / Copilot",
    install: "brew install gh  (on the theyOS host, with an active Copilot subscription)",
    login: "gh auth login  (sets COPILOT_GITHUB_TOKEN or GH_TOKEN on the host)",
    note: "GitHub token lives on the theyOS host, not in the claw.",
  },
};

// Providers that we can actually hit from this preview through Vite dev
// proxies (see vite.config.ts → server.proxy). Anything not listed here
// falls back to a "preview only — key saved locally" path that does NOT
// touch the network.
type LiveTestConfig = {
  models_path: string;
  auth:
    | { type: "bearer" }
    | { type: "header"; name: string; extra?: Record<string, string> };
};

const LIVE_TEST: Partial<Record<CloudProviderId, LiveTestConfig>> = {
  zai: { models_path: "/llm-test/zai/models", auth: { type: "bearer" } },
  openai: { models_path: "/llm-test/openai/models", auth: { type: "bearer" } },
  anthropic: {
    models_path: "/llm-test/anthropic/models",
    auth: {
      type: "header",
      name: "x-api-key",
      extra: { "anthropic-version": "2023-06-01" },
    },
  },
  deepseek: { models_path: "/llm-test/deepseek/models", auth: { type: "bearer" } },
  moonshot: { models_path: "/llm-test/moonshot/models", auth: { type: "bearer" } },
};

type TestResult =
  | {
      kind: "ok";
      provider: CloudProviderId;
      endpoint: string;
      status: number;
      latency_ms: number;
      models_count: number;
      sample_models: string[];
    }
  | {
      kind: "error";
      provider: CloudProviderId;
      endpoint: string;
      status?: number;
      latency_ms: number;
      error: string;
    }
  | {
      kind: "preview-only";
      provider: CloudProviderId;
      note: string;
    };

async function testConnection(
  provider: CloudProviderId,
  credential: string,
): Promise<TestResult> {
  const cfg = LIVE_TEST[provider];
  if (!cfg) {
    return {
      kind: "preview-only",
      provider,
      note: `live test not wired for ${PROVIDER_LABEL[provider]} in this preview. key saved to local state only (the host-side proxy will probe it in production).`,
    };
  }

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cfg.auth.type === "bearer") {
    headers["Authorization"] = `Bearer ${credential}`;
  } else {
    headers[cfg.auth.name] = credential;
    if (cfg.auth.extra) Object.assign(headers, cfg.auth.extra);
  }

  const start = performance.now();
  try {
    const response = await fetch(cfg.models_path, { method: "GET", headers });
    const latency_ms = Math.round(performance.now() - start);
    const text = await response.text();
    let body: unknown = null;
    try {
      body = JSON.parse(text);
    } catch {
      /* leave body null on non-JSON */
    }
    if (!response.ok) {
      const b = body as { error?: { message?: string }; message?: string } | null;
      const msg =
        b?.error?.message ?? b?.message ?? text.slice(0, 200) ?? "request failed";
      return {
        kind: "error",
        provider,
        endpoint: cfg.models_path,
        status: response.status,
        latency_ms,
        error: msg,
      };
    }
    const b = body as { data?: Array<{ id: string }> } | null;
    const items = b?.data ?? [];
    return {
      kind: "ok",
      provider,
      endpoint: cfg.models_path,
      status: response.status,
      latency_ms,
      models_count: items.length,
      sample_models: items.slice(0, 6).map((m) => m.id),
    };
  } catch (err) {
    const latency_ms = Math.round(performance.now() - start);
    return {
      kind: "error",
      provider,
      endpoint: cfg.models_path,
      latency_ms,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function TestResultPanel({ result }: { result: TestResult }) {
  const isOk = result.kind === "ok";
  const isError = result.kind === "error";
  const color = isOk ? "#22c55e" : isError ? "#ef4444" : "#f59e0b";
  const title =
    isOk
      ? "live test passed"
      : isError
      ? "live test failed"
      : "preview-only";

  return (
    <div
      role="status"
      style={{
        border: `1px solid ${color}`,
        borderRadius: "6px",
        padding: "10px 12px",
        background: "var(--bg-secondary, transparent)",
        fontSize: "12px",
        lineHeight: 1.5,
      }}
    >
      <p style={{ margin: 0, fontWeight: "bold", color }}>
        {isOk ? "✓" : isError ? "✗" : "ⓘ"} {title}
      </p>
      {result.kind === "ok" && (
        <>
          <p style={{ margin: "6px 0 0 0" }}>
            <strong>GET {result.endpoint}</strong> → HTTP {result.status} in {result.latency_ms}ms
          </p>
          <p style={{ margin: "4px 0 0 0" }}>
            {result.models_count} model{result.models_count === 1 ? "" : "s"} reachable with this key
            {result.sample_models.length > 0 && ":"}
          </p>
          {result.sample_models.length > 0 && (
            <code
              style={{
                display: "block",
                marginTop: "4px",
                padding: "4px 6px",
                fontSize: "11px",
                color: "var(--text-muted)",
                background: "rgba(0,0,0,.04)",
                borderRadius: "4px",
                wordBreak: "break-word",
              }}
            >
              {result.sample_models.join(", ")}
              {result.models_count > result.sample_models.length && "  …"}
            </code>
          )}
        </>
      )}
      {result.kind === "error" && (
        <>
          <p style={{ margin: "6px 0 0 0" }}>
            <strong>GET {result.endpoint}</strong>
            {result.status != null && ` → HTTP ${result.status}`}
            {" "}({result.latency_ms}ms)
          </p>
          <p style={{ margin: "4px 0 0 0", color }}>
            {result.error}
          </p>
        </>
      )}
      {result.kind === "preview-only" && (
        <p style={{ margin: "6px 0 0 0", color: "var(--text-muted)" }}>
          {result.note}
        </p>
      )}
    </div>
  );
}

// ── Catalog (real specs, public as of early 2026) ───────────────────────────
const INITIAL_MODELS: Model[] = [
  // ── Local ─────────────────────────────────────────────────────────────────
  {
    kind: "local",
    id: "local:mlx:qwen3-coder-30b-a3b",
    display_name: "Qwen3 Coder 30B A3B Instruct",
    technical_id: "mlx-community/Qwen3-Coder-30B-A3B-Instruct-4bit",
    provider: "mlx",
    tagline: "Alibaba code MoE — 30B total, only 3B active per token",
    quality: 5,
    parameters_b: 30,
    parameters_active_b: 3,
    quantization: "4-bit MLX",
    context_tokens: 262_144,
    capabilities: ["code", "tools", "long-context"],
    download_size_gb: 17,
    min_ram_gb: 24,
    released: "2025-09",
    compatibility: "fits-well",
    install: "ready",
    measured_tokps: 42,
    speed_class: "fast",
  },
  {
    kind: "local",
    id: "local:mlx:qwen3-4b-instruct",
    display_name: "Qwen3 4B Instruct 2507",
    technical_id: "mlx-community/Qwen3-4B-Instruct-2507-4bit",
    provider: "mlx",
    tagline: "dense 4B — light on Mac, solid for everyday chat",
    quality: 3,
    parameters_b: 4,
    quantization: "4-bit MLX",
    context_tokens: 32_768,
    capabilities: ["chat", "writing"],
    download_size_gb: 3,
    min_ram_gb: 8,
    released: "2025-07",
    compatibility: "fits-well",
    install: "ready",
    measured_tokps: 118,
    speed_class: "fast",
  },
  {
    kind: "local",
    id: "local:ollama:deepseek-coder-v2-16b",
    display_name: "DeepSeek Coder V2 Lite 16B",
    technical_id: "deepseek-coder-v2:16b",
    provider: "ollama",
    tagline: "DeepSeek code MoE — 16B total, 2.4B active",
    quality: 4,
    parameters_b: 16,
    parameters_active_b: 2.4,
    quantization: "Q4_K_M",
    context_tokens: 131_072,
    capabilities: ["code", "tools"],
    download_size_gb: 10,
    min_ram_gb: 16,
    released: "2024-06",
    compatibility: "fits-well",
    install: "not_installed",
    speed_class: "unmeasured",
  },
  {
    kind: "local",
    id: "local:ollama:llama3-1-70b",
    display_name: "Llama 3.1 70B Instruct",
    technical_id: "llama3.1:70b",
    provider: "ollama",
    tagline: "Meta's dense 70B — high quality, but needs a beefy machine",
    quality: 4,
    parameters_b: 70,
    quantization: "Q4_K_M",
    context_tokens: 131_072,
    capabilities: ["chat", "writing", "code", "tools"],
    download_size_gb: 40,
    min_ram_gb: 80,
    released: "2024-07",
    compatibility: "wont-fit",
    install: "not_installed",
    speed_class: "unmeasured",
  },
  {
    kind: "local",
    id: "local:llamacpp:mistral-7b-v03",
    display_name: "Mistral 7B Instruct v0.3",
    technical_id: "local",
    provider: "llamacpp",
    tagline: "dense 7B — stable, great for long-form writing",
    quality: 3,
    parameters_b: 7,
    quantization: "Q4_K_M GGUF",
    context_tokens: 32_768,
    capabilities: ["chat", "writing"],
    download_size_gb: 4.5,
    min_ram_gb: 8,
    released: "2024-05",
    compatibility: "fits-well",
    install: "not_installed",
    speed_class: "unmeasured",
  },

  // ── Cloud (model refs verbatim from openclaw/openclaw provider plugins) ───
  {
    kind: "cloud",
    id: "anthropic/claude-opus-4-7",
    display_name: "Claude Opus 4.7",
    technical_id: "anthropic/claude-opus-4-7",
    provider: "anthropic",
    tagline: "Anthropic's flagship — deep reasoning, tool use, complex code",
    quality: 5,
    context_tokens: 200_000,
    capabilities: ["code", "reasoning", "writing", "chat", "tools"],
    plan_available: {
      name: "Claude Pro / Max (includes Claude Code)",
      url: "https://claude.ai/upgrade",
    },
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "anthropic/claude-opus-4-6",
    display_name: "Claude Opus 4.6",
    technical_id: "anthropic/claude-opus-4-6",
    provider: "anthropic",
    tagline: "previous stable — also via Claude Code",
    quality: 5,
    context_tokens: 200_000,
    capabilities: ["code", "reasoning", "writing", "chat", "tools"],
    plan_available: {
      name: "Claude Pro / Max (includes Claude Code)",
      url: "https://claude.ai/upgrade",
    },
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "openai/gpt-5.5",
    display_name: "GPT-5.5",
    technical_id: "openai/gpt-5.5",
    provider: "openai",
    tagline: "OpenAI's flagship — also via ChatGPT/Codex subscription",
    quality: 5,
    context_tokens: 400_000,
    capabilities: ["chat", "writing", "code", "vision", "tools", "reasoning"],
    plan_available: {
      name: "ChatGPT Plus / Pro (Codex OAuth)",
      url: "https://openai.com/chatgpt/pricing",
      note: "access via Codex app-server harness through OAuth",
    },
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "openai/gpt-5.4-mini",
    display_name: "GPT-5.4 mini",
    technical_id: "openai/gpt-5.4-mini",
    provider: "openai",
    tagline: "smaller GPT-5 — cheap, fast",
    quality: 4,
    context_tokens: 128_000,
    capabilities: ["chat", "code", "tools"],
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "google/gemini-3.1-pro-preview",
    display_name: "Gemini 3.1 Pro",
    technical_id: "google/gemini-3.1-pro-preview",
    provider: "google",
    tagline: "native multimodal (text, image, video, audio) with dynamic thinking",
    quality: 5,
    context_tokens: 1_000_000,
    capabilities: ["chat", "code", "vision", "long-context", "reasoning", "tools"],
    plan_available: {
      name: "Gemini CLI (OAuth)",
      url: "https://github.com/google-gemini/gemini-cli",
      note: "unofficial integration via Gemini CLI — use a secondary account",
    },
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "google/gemini-3-flash-preview",
    display_name: "Gemini 3 Flash",
    technical_id: "google/gemini-3-flash-preview",
    provider: "google",
    tagline: "gen-3 Flash — fast, multimodal",
    quality: 4,
    context_tokens: 1_000_000,
    capabilities: ["chat", "code", "vision", "long-context", "tools"],
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "deepseek/deepseek-v4-flash",
    display_name: "DeepSeek V4-Flash",
    technical_id: "deepseek/deepseek-v4-flash",
    provider: "deepseek",
    tagline: "default V4 surface · thinking-capable · 1M context, 384k max output",
    quality: 5,
    context_tokens: 1_000_000,
    capabilities: ["chat", "code", "writing", "tools", "long-context"],
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "deepseek/deepseek-v4-pro",
    display_name: "DeepSeek V4-Pro",
    technical_id: "deepseek/deepseek-v4-pro",
    provider: "deepseek",
    tagline: "stronger V4 surface · 1M context, 384k max output",
    quality: 5,
    context_tokens: 1_000_000,
    capabilities: ["reasoning", "code", "writing", "tools", "long-context"],
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "zai/glm-5.1",
    display_name: "GLM 5.1",
    technical_id: "zai/glm-5.1",
    provider: "zai",
    tagline: "Z.AI GLM flagship — top quality with affordable Coding Plan",
    quality: 5,
    context_tokens: 200_000,
    capabilities: ["chat", "code", "tools", "long-context", "reasoning"],
    plan_available: {
      name: "Z.AI Coding Plan",
      url: "https://z.ai/subscribe",
    },
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "moonshot/kimi-k2.6",
    display_name: "Kimi K2.6",
    technical_id: "moonshot/kimi-k2.6",
    provider: "moonshot",
    tagline: "Moonshot Kimi — agentic, long-context · also via Kimi Membership",
    quality: 4,
    context_tokens: 200_000,
    capabilities: ["chat", "code", "agentic", "long-context", "tools"],
    plan_available: {
      name: "Kimi Membership (Kimi Code via kimi/kimi-for-coding)",
      url: "https://www.kimi.com/membership/pricing",
      note: "~300-1200 req per 5h window · quota refreshes every 7 days · endpoint api.kimi.com/coding/v1",
    },
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "moonshot/kimi-k2-thinking",
    display_name: "Kimi K2 Thinking",
    technical_id: "moonshot/kimi-k2-thinking",
    provider: "moonshot",
    tagline: "Kimi K2 reasoning mode — for harder problems",
    quality: 5,
    context_tokens: 200_000,
    capabilities: ["reasoning", "code", "long-context", "tools"],
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "qwen/qwen3.5-plus",
    display_name: "Qwen 3.5 Plus",
    technical_id: "qwen/qwen3.5-plus",
    provider: "qwen",
    tagline: "Alibaba Qwen — plan aggregates Qwen3, Kimi K2.5, GLM-5, MiniMax M2.5",
    quality: 5,
    context_tokens: 262_144,
    capabilities: ["chat", "code", "tools", "long-context", "reasoning"],
    plan_available: {
      name: "Alibaba AI Coding Plan (Lite / Pro)",
      url: "https://www.alibabacloud.com/en/campaign/ai-scene-coding",
      note: "Lite 3× Claude Code, Pro 5× Lite · aggregates Qwen + Kimi + GLM + MiniMax",
    },
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "qwen/qwen3-max",
    display_name: "Qwen 3 Max",
    technical_id: "qwen/qwen3-max",
    provider: "qwen",
    tagline: "Qwen Max — strong on code and multilingual",
    quality: 5,
    context_tokens: 262_144,
    capabilities: ["chat", "code", "writing", "tools", "long-context"],
    plan_available: {
      name: "Alibaba AI Coding Plan",
      url: "https://www.alibabacloud.com/en/campaign/ai-scene-coding",
    },
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "minimax/MiniMax-M2.7",
    display_name: "MiniMax M2.7",
    technical_id: "minimax/MiniMax-M2.7",
    provider: "minimax",
    tagline: "agentic, long-context · via API or MiniMax Coding Plan OAuth",
    quality: 4,
    context_tokens: 1_000_000,
    capabilities: ["agentic", "long-context", "tools", "chat", "code"],
    plan_available: {
      name: "MiniMax Coding Plan (OAuth)",
      url: "https://www.minimax.io/",
    },
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "xai/grok-4.3",
    display_name: "Grok 4.3",
    technical_id: "xai/grok-4.3",
    provider: "xai",
    tagline: "xAI Grok — independent provider, /fast rewrites to *-fast variants",
    quality: 4,
    context_tokens: 256_000,
    capabilities: ["chat", "code", "writing", "tools"],
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "volcengine-plan/ark-code-latest",
    display_name: "Doubao Ark Code (Volcano)",
    technical_id: "volcengine-plan/ark-code-latest",
    provider: "volcengine",
    tagline: "Volcano Engine (China) — Doubao + aggregates Kimi K2.5, GLM 4.7",
    quality: 4,
    context_tokens: 128_000,
    capabilities: ["code", "chat", "tools"],
    plan_available: {
      name: "Volcano Engine Coding Plan",
      url: "https://www.volcengine.com/",
      note: "China region · also aggregates Kimi K2.5, GLM 4.7, DeepSeek V3.2",
    },
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "byteplus-plan/ark-code-latest",
    display_name: "BytePlus Ark Code",
    technical_id: "byteplus-plan/ark-code-latest",
    provider: "byteplus",
    tagline: "international Volcano — Seed, Kimi K2.5, GLM 4.7",
    quality: 4,
    context_tokens: 128_000,
    capabilities: ["code", "chat", "tools"],
    plan_available: {
      name: "BytePlus Coding Plan",
      url: "https://www.byteplus.com/",
    },
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "cerebras/zai-glm-4.7",
    display_name: "GLM 4.7 (Cerebras)",
    technical_id: "cerebras/zai-glm-4.7",
    provider: "cerebras",
    tagline: "Cerebras runs GLM on ultra-fast wafer-scale inference",
    quality: 4,
    context_tokens: 128_000,
    capabilities: ["chat", "code", "tools"],
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "mistral/mistral-large-latest",
    display_name: "Mistral Large",
    technical_id: "mistral/mistral-large-latest",
    provider: "mistral",
    tagline: "Mistral Large — European generalist",
    quality: 4,
    context_tokens: 128_000,
    capabilities: ["chat", "code", "writing", "tools"],
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "openrouter/auto",
    display_name: "OpenRouter Auto",
    technical_id: "openrouter/auto",
    provider: "openrouter",
    tagline: "aggregator — one key gives access to hundreds of models",
    quality: 4,
    context_tokens: 200_000,
    capabilities: ["chat", "code", "writing", "tools"],
    connection: "no-credential",
  },
  {
    kind: "cloud",
    id: "kilocode/kilo/auto",
    display_name: "Kilo Auto",
    technical_id: "kilocode/kilo/auto",
    provider: "kilocode",
    tagline: "Kilo gateway — routes to the best model for the task",
    quality: 4,
    context_tokens: 200_000,
    capabilities: ["chat", "code", "tools"],
    connection: "no-credential",
  },
];

// ── UX-facing labels ────────────────────────────────────────────────────────

function compatLabel(c: Compatibility): string {
  switch (c) {
    case "fits-well": return "runs well";
    case "should-fit": return "should run";
    case "tight": return "tight fit";
    case "wont-fit": return "won't fit";
    case "untested": return "untested";
  }
}
function compatColor(c: Compatibility): string {
  switch (c) {
    case "fits-well": return "#22c55e";
    case "should-fit": return "#86c46b";
    case "tight": return "#f59e0b";
    case "wont-fit": return "var(--text-muted)";
    case "untested": return "var(--text-muted)";
  }
}

function connectionLabel(c: ConnectionState): string {
  switch (c) {
    case "ok": return "connected";
    case "no-credential": return "no credential";
    case "invalid-key": return "invalid key";
    case "untested": return "untested";
  }
}
function connectionColor(c: ConnectionState): string {
  switch (c) {
    case "ok": return "#22c55e";
    case "no-credential": return "var(--text-muted)";
    case "invalid-key": return "#ef4444";
    case "untested": return "var(--text-muted)";
  }
}

function speedLabel(s: SpeedClass, tokps?: number): string {
  switch (s) {
    case "fast": return tokps ? `fast on this machine · ${tokps} tok/s` : "fast";
    case "ok": return tokps ? `ok · ${tokps} tok/s` : "ok";
    case "slow": return tokps ? `slow · ${tokps} tok/s — works, but you'll wait` : "slow";
    case "unmeasured": return "not measured yet";
  }
}
function speedColor(s: SpeedClass): string {
  switch (s) {
    case "fast": return "#22c55e";
    case "ok": return "#86c46b";
    case "slow": return "#f59e0b";
    case "unmeasured": return "var(--text-muted)";
  }
}

// ── Number / spec formatters ────────────────────────────────────────────────

function fmtContext(t: number): string {
  if (t >= 1_000_000) {
    const v = t / 1_000_000;
    return Number.isInteger(v) ? `${v}M` : `${v.toFixed(1)}M`;
  }
  if (t >= 1_000) return `${Math.round(t / 1000)}k`;
  return String(t);
}

function fmtParams(model: LocalModel): string {
  if (model.parameters_active_b) {
    return `${model.parameters_b}B (${model.parameters_active_b}B active · MoE) · ${model.quantization}`;
  }
  return `${model.parameters_b}B dense · ${model.quantization}`;
}

function fmtMonth(yyyymm: string): string {
  const [y, m] = yyyymm.split("-");
  const months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
  const mi = Number(m) - 1;
  return mi >= 0 && mi < 12 ? `${months[mi]} ${y}` : yyyymm;
}

// 1-5 quality bar with filled/empty squares — readable in both themes.
function QualityBar({ value }: { value: 1 | 2 | 3 | 4 | 5 }) {
  return (
    <span aria-label={`quality ${value} of 5`} style={{ letterSpacing: "1px", fontFamily: "inherit" }}>
      {Array.from({ length: 5 }, (_, i) => (
        <span key={i} style={{ color: i < value ? "#22c55e" : "var(--text-muted)" }}>
          {i < value ? "■" : "□"}
        </span>
      ))}
    </span>
  );
}

function Pill({
  children,
  color,
}: {
  children: React.ReactNode;
  color?: string;
}) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
        padding: "2px 8px",
        borderRadius: "999px",
        border: `1px solid ${color ?? "var(--text-muted)"}`,
        color: color ?? "inherit",
        fontSize: "11px",
        textTransform: "uppercase",
        letterSpacing: "0.5px",
      }}
    >
      {children}
    </span>
  );
}

// ── Compatibility check ─────────────────────────────────────────────────────
function checkCompatibility(model: LocalModel): Compatibility {
  if (model.min_ram_gb > MOCK_HOST.total_ram_gb) return "wont-fit";
  if (model.min_ram_gb > MOCK_HOST.available_ram_gb) return "tight";
  if (model.min_ram_gb * 1.5 <= MOCK_HOST.available_ram_gb) return "fits-well";
  return "should-fit";
}

// ── Card components ─────────────────────────────────────────────────────────

function TechIdDisclosure({ id }: { id: string }) {
  return (
    <details style={{ marginTop: "4px" }}>
      <summary
        className="network-detail muted"
        style={{ cursor: "pointer", listStyle: "revert", padding: 0 }}
      >
        model ref
      </summary>
      <code
        style={{
          display: "block",
          marginTop: "4px",
          padding: "4px 6px",
          fontSize: "11px",
          wordBreak: "break-all",
          color: "var(--text-muted)",
          background: "var(--bg-secondary, rgba(0,0,0,.04))",
          borderRadius: "4px",
        }}
      >
        {id}
      </code>
    </details>
  );
}

function ModelCard({
  model,
  isActive,
  busy,
  onInstall,
  onUninstall,
  onSetActive,
  onConnect,
}: {
  model: Model;
  isActive: boolean;
  busy: boolean;
  onInstall: (id: string) => void;
  onUninstall: (id: string) => void;
  onSetActive: (id: string) => void;
  onConnect: (id: string) => void;
}) {
  return (
    <div className="network-card" data-active={isActive ? "true" : undefined}>
      <div className="network-card-header">
        <strong>{model.display_name}</strong>
        <Pill color="var(--text-muted)">
          {model.kind === "local" ? "local" : "cloud"} · {PROVIDER_LABEL[model.provider]}
        </Pill>
        {isActive && <Pill color="#22c55e">active</Pill>}
      </div>

      <div className="network-card-body">
        <p className="network-detail muted">{model.tagline}</p>

        <p className="network-detail">
          <span className="network-label">quality</span>
          <QualityBar value={model.quality} />
        </p>

        <p className="network-detail">
          <span className="network-label">context</span>
          <span>{fmtContext(model.context_tokens)} tokens</span>
        </p>

        {model.kind === "local" && (
          <>
            <p className="network-detail">
              <span className="network-label">parameters</span>
              <span>{fmtParams(model)}</span>
            </p>
            <p className="network-detail">
              <span className="network-label">compatibility</span>
              <span style={{ color: compatColor(model.compatibility) }}>
                {compatLabel(model.compatibility)}
              </span>
            </p>
            <p className="network-detail">
              <span className="network-label">disk · ram</span>
              <span>{model.download_size_gb} GB · {model.min_ram_gb} GB min</span>
            </p>
            {model.released && (
              <p className="network-detail">
                <span className="network-label">released</span>
                <span>{fmtMonth(model.released)}</span>
              </p>
            )}
            {model.install === "ready" && (
              <p className="network-detail">
                <span className="network-label">speed</span>
                <span style={{ color: speedColor(model.speed_class) }}>
                  {speedLabel(model.speed_class, model.measured_tokps)}
                </span>
              </p>
            )}
            <TechIdDisclosure id={model.technical_id} />
          </>
        )}

        {model.kind === "cloud" && (
          <>
            {model.knowledge_cutoff && (
              <p className="network-detail">
                <span className="network-label">knowledge cutoff</span>
                <span>{fmtMonth(model.knowledge_cutoff)}</span>
              </p>
            )}

            {model.active_billing === "plan" && model.plan_available && (
              <p className="network-detail">
                <span className="network-label">billing</span>
                <span style={{ color: "#22c55e" }}>via {model.plan_available.name}</span>
              </p>
            )}

            {model.plan_available && model.active_billing !== "plan" && (
              <>
                <p className="network-detail">
                  <span className="network-label">coding plan</span>
                  <span>
                    {model.plan_available.url ? (
                      <a
                        href={model.plan_available.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ color: "inherit", textDecoration: "underline" }}
                      >
                        {model.plan_available.name}
                      </a>
                    ) : (
                      model.plan_available.name
                    )}
                  </span>
                </p>
                {model.plan_available.note && (
                  <p
                    className="network-detail muted"
                    style={{ fontSize: "11px", lineHeight: 1.4 }}
                  >
                    {model.plan_available.note}
                  </p>
                )}
              </>
            )}

            <p className="network-detail">
              <span className="network-label">connection</span>
              <span style={{ color: connectionColor(model.connection) }}>
                {connectionLabel(model.connection)}
              </span>
            </p>

            <TechIdDisclosure id={model.technical_id} />
          </>
        )}
      </div>

      <div style={{ marginTop: "auto", paddingTop: "8px", display: "flex", gap: "6px", flexWrap: "wrap" }}>
        {model.kind === "local" && model.install === "not_installed" && model.compatibility !== "wont-fit" && (
          <button
            type="button"
            className="network-expose-btn"
            onClick={() => onInstall(model.id)}
            disabled={busy}
          >
            install
          </button>
        )}
        {model.kind === "local" && model.install === "not_installed" && model.compatibility === "wont-fit" && (
          <button type="button" className="network-expose-btn" disabled title="model won't fit on this machine">
            won't fit
          </button>
        )}
        {model.kind === "local" && model.install === "installing" && (
          <button type="button" className="network-expose-btn" data-variant="progress" disabled>
            downloading + testing...
          </button>
        )}
        {model.kind === "local" && model.install === "ready" && !isActive && (
          <button
            type="button"
            className="network-expose-btn"
            onClick={() => onSetActive(model.id)}
            disabled={busy}
          >
            set as active
          </button>
        )}
        {model.kind === "local" && model.install === "ready" && (
          <button
            type="button"
            className="network-expose-btn"
            data-variant="destructive"
            onClick={() => onUninstall(model.id)}
            disabled={busy}
          >
            remove
          </button>
        )}
        {model.kind === "local" && model.install === "failed" && (
          <button
            type="button"
            className="network-expose-btn"
            onClick={() => onInstall(model.id)}
            disabled={busy}
          >
            retry
          </button>
        )}

        {model.kind === "cloud" && model.connection !== "ok" && (
          <button
            type="button"
            className="network-expose-btn"
            onClick={() => onConnect(model.id)}
            disabled={busy}
          >
            connect
          </button>
        )}
        {model.kind === "cloud" && model.connection === "ok" && !isActive && (
          <button
            type="button"
            className="network-expose-btn"
            onClick={() => onSetActive(model.id)}
            disabled={busy}
          >
            set as active
          </button>
        )}
      </div>
    </div>
  );
}

// ── Add-provider sheet ──────────────────────────────────────────────────────

function AddProviderForm({
  initialProvider,
  onAdd,
  onCancel,
}: {
  initialProvider?: CloudProviderId;
  onAdd: (provider: CloudProviderId, mode: BillingMode, result: TestResult) => void;
  onCancel: () => void;
}) {
  const [provider, setProvider] = useState<CloudProviderId>(initialProvider ?? "openai");
  const [mode, setMode] = useState<BillingMode>("api");
  const [credential, setCredential] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<TestResult | null>(null);

  const planSupported = PROVIDERS_WITH_PLAN.has(provider);
  const liveTestable = LIVE_TEST[provider] != null;
  // Plan mode for some providers is OAuth-bound to a CLI tool on the host —
  // there is literally nothing to paste here. We render instructions instead.
  const planIsCliOAuth =
    mode === "plan" && PLAN_AUTH_KIND[provider] === "cli-oauth";
  const cliInstructions = planIsCliOAuth ? CLI_OAUTH_INSTRUCTIONS[provider] : undefined;

  // Reset mode when switching to a provider that doesn't have a plan;
  // also clear previous test result so the panel doesn't lie.
  const handleProviderChange = (next: CloudProviderId) => {
    setProvider(next);
    if (!PROVIDERS_WITH_PLAN.has(next)) setMode("api");
    setResult(null);
    setError(null);
    setCredential("");
  };

  // Switching to/from cli-oauth plan mode clears credential since the field
  // appears/disappears between modes.
  const handleModeChange = (next: BillingMode) => {
    setMode(next);
    setResult(null);
    setError(null);
    setCredential("");
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);

    // CLI-OAuth plans: nothing to test from the browser. Just record the
    // user's intent to use the host CLI for this provider. Production will
    // detect the actual CLI auth at claw startup.
    if (planIsCliOAuth) {
      const r: TestResult = {
        kind: "preview-only",
        provider,
        note: `using ${cliInstructions?.cli ?? "host CLI"} OAuth. theyOS will detect the login on the host at claw startup. the browser never sees this credential.`,
      };
      setResult(r);
      onAdd(provider, mode, r);
      return;
    }

    const value = credential.trim();
    if (!value) {
      setError(mode === "api" ? "paste an API key" : "paste the plan token");
      return;
    }
    setTesting(true);
    const r = await testConnection(provider, value);
    setResult(r);
    setTesting(false);
    // Only flip the card to "connected" when the live test actually passed.
    // Preview-only providers also flip — they keep working in this UX preview
    // even though we didn't touch the network. Errors stay in the form so
    // the user can fix the key and retry.
    if (r.kind === "ok" || r.kind === "preview-only") {
      onAdd(provider, mode, r);
      setCredential("");
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      style={{
        border: "1px solid var(--text-muted)",
        borderRadius: "8px",
        padding: "12px",
        marginBottom: "16px",
        display: "flex",
        flexDirection: "column",
        gap: "10px",
        background: "var(--bg-secondary, transparent)",
      }}
    >
      <p style={{ margin: 0, fontSize: "12px", color: "var(--text-muted)" }}>
        the credential lives in the host Keychain. it never enters the claw — the claw only talks to 127.0.0.1.
      </p>

      <label style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
        <span className="network-label">provider</span>
        <select
          value={provider}
          onChange={(e) => handleProviderChange(e.target.value as CloudProviderId)}
          style={{ padding: "6px 8px" }}
        >
          <optgroup label="major labs">
            <option value="anthropic">Anthropic (Claude)</option>
            <option value="openai">OpenAI (GPT)</option>
            <option value="google">Google (Gemini)</option>
            <option value="xai">xAI (Grok)</option>
          </optgroup>
          <optgroup label="chinese labs">
            <option value="deepseek">DeepSeek</option>
            <option value="zai">Z.AI / GLM</option>
            <option value="moonshot">Moonshot (Kimi)</option>
            <option value="qwen">Alibaba (Qwen)</option>
            <option value="minimax">MiniMax</option>
            <option value="stepfun">StepFun</option>
            <option value="volcengine">Volcano Engine (Doubao · China)</option>
            <option value="byteplus">BytePlus (Volcano international)</option>
            <option value="qianfan">Baidu Qianfan</option>
          </optgroup>
          <optgroup label="aggregators / gateways">
            <option value="openrouter">OpenRouter</option>
            <option value="vercel-ai-gateway">Vercel AI Gateway</option>
            <option value="kilocode">Kilo Gateway</option>
            <option value="opencode">OpenCode Zen</option>
          </optgroup>
          <optgroup label="specialized inference">
            <option value="cerebras">Cerebras (WSE)</option>
            <option value="groq">Groq (LPU)</option>
            <option value="together">Together AI</option>
            <option value="nvidia">NVIDIA NIM</option>
            <option value="mistral">Mistral</option>
            <option value="huggingface">Hugging Face</option>
          </optgroup>
          <optgroup label="subscription / OAuth">
            <option value="github-copilot">GitHub Copilot</option>
          </optgroup>
        </select>
      </label>

      {planSupported && (
        <fieldset
          style={{
            border: "1px solid var(--text-muted)",
            borderRadius: "6px",
            padding: "8px 10px",
            display: "flex",
            flexDirection: "column",
            gap: "6px",
            margin: 0,
          }}
        >
          <legend className="network-label" style={{ padding: "0 4px" }}>
            billing
          </legend>
          <label style={{ display: "flex", alignItems: "flex-start", gap: "6px", cursor: "pointer" }}>
            <input
              type="radio"
              name="billing-mode"
              value="api"
              checked={mode === "api"}
              onChange={() => handleModeChange("api")}
            />
            <span>
              <strong>API key</strong> — pay per token used
            </span>
          </label>
          <label style={{ display: "flex", alignItems: "flex-start", gap: "6px", cursor: "pointer" }}>
            <input
              type="radio"
              name="billing-mode"
              value="plan"
              checked={mode === "plan"}
              onChange={() => handleModeChange("plan")}
            />
            <span>
              <strong>coding plan</strong> — monthly subscription, near-unlimited usage
            </span>
          </label>
        </fieldset>
      )}

      {planIsCliOAuth && cliInstructions ? (
        <div
          style={{
            border: "1px solid var(--text-muted)",
            borderRadius: "6px",
            padding: "10px 12px",
            background: "var(--bg-secondary, transparent)",
            fontSize: "12px",
            lineHeight: 1.5,
            display: "flex",
            flexDirection: "column",
            gap: "8px",
          }}
        >
          <p style={{ margin: 0, fontWeight: "bold" }}>
            this plan uses {cliInstructions.cli} OAuth — no token to paste
          </p>
          <ol style={{ margin: 0, paddingLeft: "20px", display: "flex", flexDirection: "column", gap: "6px" }}>
            <li>
              install on the host:
              <code style={{ display: "block", marginTop: "2px", padding: "4px 6px", fontSize: "11px", background: "rgba(0,0,0,.06)", borderRadius: "4px", wordBreak: "break-all" }}>
                {cliInstructions.install}
              </code>
            </li>
            <li>
              run on the host:
              <code style={{ display: "block", marginTop: "2px", padding: "4px 6px", fontSize: "11px", background: "rgba(0,0,0,.06)", borderRadius: "4px", wordBreak: "break-all" }}>
                {cliInstructions.login}
              </code>
            </li>
            <li>click <strong>save</strong> below — theyOS will detect the CLI login at claw startup.</li>
          </ol>
          {cliInstructions.note && (
            <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "11px" }}>
              {cliInstructions.note}
            </p>
          )}
        </div>
      ) : (
        <label style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
          <span className="network-label">
            {mode === "plan" ? "plan API key" : "API key"}
          </span>
          <input
            type="password"
            value={credential}
            onChange={(e) => setCredential(e.target.value)}
            placeholder={mode === "plan" ? "plan API key (sk-..., dashboard-issued)" : "sk-..."}
            autoComplete="off"
            spellCheck={false}
            style={{ padding: "6px 8px", fontFamily: "inherit" }}
          />
        </label>
      )}

      {!planIsCliOAuth && !liveTestable && (
        <p style={{ margin: 0, fontSize: "11px", color: "#f59e0b" }}>
          ⓘ {PROVIDER_LABEL[provider]} isn't wired for live testing in this preview —
          the key won't actually be probed. flip the card to "connected" for UX flow only.
        </p>
      )}

      {error && <p className="form-error" style={{ margin: 0 }}>{error}</p>}

      <div style={{ display: "flex", gap: "6px" }}>
        <button type="submit" className="provider-save-btn" disabled={testing}>
          {testing
            ? "testing..."
            : planIsCliOAuth
            ? "save"
            : liveTestable
            ? "test & save"
            : "save"}
        </button>
        <button type="button" className="network-expose-btn" onClick={onCancel} disabled={testing}>
          {result?.kind === "ok" || result?.kind === "preview-only" ? "close" : "cancel"}
        </button>
      </div>

      {result && <TestResultPanel result={result} />}
    </form>
  );
}

// ── Active-model pill ───────────────────────────────────────────────────────

function ActiveModelPill({
  activeModel,
  installed,
  onSetActive,
}: {
  activeModel: Model | undefined;
  installed: Model[];
  onSetActive: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);

  const label = activeModel
    ? `${activeModel.display_name} · ${PROVIDER_LABEL[activeModel.provider]}`
    : "no active model";

  return (
    <div style={{ position: "relative", marginBottom: "16px" }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="provider-save-btn"
        style={{
          padding: "10px 14px",
          fontSize: "13px",
          display: "inline-flex",
          alignItems: "center",
          gap: "8px",
        }}
        aria-expanded={open}
      >
        <span style={{ opacity: 0.6 }}>active model:</span>
        <strong>{label}</strong>
        <span aria-hidden style={{ marginLeft: "4px" }}>{open ? "▴" : "▾"}</span>
      </button>
      {open && (
        <div
          role="menu"
          style={{
            position: "absolute",
            top: "calc(100% + 4px)",
            left: 0,
            zIndex: 30,
            background: "var(--bg-primary, #fff)",
            border: "1px solid var(--text-muted)",
            borderRadius: "8px",
            padding: "4px",
            minWidth: "320px",
            maxHeight: "60vh",
            overflowY: "auto",
            boxShadow: "0 4px 12px rgba(0,0,0,0.25)",
          }}
        >
          {installed.length === 0 && (
            <p className="network-detail muted" style={{ padding: "8px" }}>
              install or connect a model first
            </p>
          )}
          {installed.map((m) => (
            <button
              key={m.id}
              role="menuitem"
              type="button"
              onClick={() => {
                onSetActive(m.id);
                setOpen(false);
              }}
              style={{
                display: "flex",
                width: "100%",
                gap: "8px",
                padding: "8px",
                background: m.id === activeModel?.id ? "var(--bg-secondary, transparent)" : "transparent",
                border: "none",
                cursor: "pointer",
                textAlign: "left",
                color: "inherit",
                borderRadius: "4px",
                fontFamily: "inherit",
              }}
            >
              <span style={{ flex: 1 }}>
                <strong>{m.display_name}</strong>
                <br />
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                  {m.kind === "local" ? "local" : "cloud"} · {PROVIDER_LABEL[m.provider]}
                  {m.kind === "cloud" && m.active_billing === "plan" && " · via plan"}
                </span>
              </span>
              {m.id === activeModel?.id && <span style={{ color: "#22c55e" }}>{"✓"}</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export function ModelsPage() {
  const [models, setModels] = useState<Model[]>(() =>
    INITIAL_MODELS.map((m) =>
      m.kind === "local" ? { ...m, compatibility: checkCompatibility(m) } : m,
    ),
  );
  const [tab, setTab] = useState<ModelKind>("local");
  const [activeId, setActiveId] = useState<string | null>("local:mlx:qwen3-coder-30b-a3b");
  const [showAddProvider, setShowAddProvider] = useState(false);
  const [pendingProvider, setPendingProvider] = useState<CloudProviderId | undefined>(undefined);
  const [busy, setBusy] = useState<string | null>(null);

  const grouped = useMemo(() => {
    const local = models.filter((m): m is LocalModel => m.kind === "local");
    const cloud = models.filter((m): m is CloudModel => m.kind === "cloud");
    return { local, cloud };
  }, [models]);

  const activeModel = useMemo(() => models.find((m) => m.id === activeId), [models, activeId]);

  const installedOrConnected = useMemo(
    () =>
      models.filter(
        (m) =>
          (m.kind === "local" && m.install === "ready") ||
          (m.kind === "cloud" && m.connection === "ok"),
      ),
    [models],
  );

  const visible = tab === "local" ? grouped.local : grouped.cloud;

  // ── Mock actions ───────────────────────────────────────────────────────
  const updateModel = (id: string, mut: (m: Model) => Model) => {
    setModels((prev) => prev.map((m) => (m.id === id ? mut(m) : m)));
  };

  const handleInstall = (id: string) => {
    setBusy(id);
    updateModel(id, (m) => (m.kind === "local" ? { ...m, install: "installing" } : m));
    window.setTimeout(() => {
      updateModel(id, (m) => {
        if (m.kind !== "local") return m;
        const tokps = 60 + Math.floor(Math.random() * 60);
        const speed: SpeedClass = tokps > 80 ? "fast" : tokps > 30 ? "ok" : "slow";
        return { ...m, install: "ready", measured_tokps: tokps, speed_class: speed };
      });
      setBusy(null);
    }, 1200);
  };

  const handleUninstall = (id: string) => {
    setBusy(id);
    window.setTimeout(() => {
      updateModel(id, (m) =>
        m.kind === "local"
          ? { ...m, install: "not_installed", measured_tokps: undefined, speed_class: "unmeasured" }
          : m,
      );
      if (activeId === id) setActiveId(null);
      setBusy(null);
    }, 400);
  };

  const handleSetActive = (id: string) => {
    setActiveId(id);
  };

  // Card "connect" no longer fakes a successful connection. It opens the
  // AddProviderForm pre-filled with that card's provider so the user can
  // paste a key and run a real (or preview-only) test.
  const handleConnect = (id: string) => {
    const model = models.find((m) => m.id === id);
    if (model?.kind !== "cloud") return;
    setPendingProvider(model.provider);
    setShowAddProvider(true);
    // Scroll the form into view — the user clicked from a card, which may be
    // far down the page.
    requestAnimationFrame(() => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  };

  const handleAddProvider = (
    provider: CloudProviderId,
    mode: BillingMode,
    _result: TestResult,
  ) => {
    setModels((prev) =>
      prev.map((m) =>
        m.kind === "cloud" && m.provider === provider
          ? { ...m, connection: "ok", active_billing: mode }
          : m,
      ),
    );
    // Keep the form open so the user can read the TestResultPanel.
    // The form's "close" button (renamed once the result is in) closes it.
  };

  const handleCloseAddProvider = () => {
    setShowAddProvider(false);
    setPendingProvider(undefined);
  };

  return (
    <section className="page-section clawstore">
      <header className="page-header">
        <p className="path">~/soyeht/admin/models</p>
        <h1>models</h1>
        <p className="subtitle">
          // llm engine powering the claws · preview · 5 providers live-testable (zai, openai, anthropic, deepseek, moonshot)
        </p>
        <button
          type="button"
          className="provider-save-btn"
          onClick={() => {
            if (showAddProvider) {
              handleCloseAddProvider();
            } else {
              setPendingProvider(undefined);
              setShowAddProvider(true);
            }
          }}
        >
          {showAddProvider ? "close" : "+ add provider"}
        </button>
      </header>

      <p
        style={{
          margin: "8px 0 16px 0",
          padding: "8px 12px",
          border: "1px dashed var(--text-muted)",
          borderRadius: "6px",
          fontSize: "12px",
          color: "var(--text-muted)",
        }}
      >
        your credential never enters the claw. a local proxy injects auth on the host
        and the claw only talks to 127.0.0.1 — prompt injection cannot read your keys.
      </p>

      <ActiveModelPill
        activeModel={activeModel}
        installed={installedOrConnected}
        onSetActive={handleSetActive}
      />

      {showAddProvider && (
        <AddProviderForm
          // key forces a fresh form state when the user opens it for a
          // different provider — otherwise stale credential/result lingers.
          key={pendingProvider ?? "no-pending"}
          initialProvider={pendingProvider}
          onAdd={handleAddProvider}
          onCancel={handleCloseAddProvider}
        />
      )}

      <div role="tablist" aria-label="model kind" className="cs-segmented">
        <button
          type="button"
          role="tab"
          aria-selected={tab === "local"}
          onClick={() => setTab("local")}
          className={`cs-segment${tab === "local" ? " cs-segment-active" : ""}`}
        >
          <span>local</span>
          <span className="cs-count">{grouped.local.length}</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "cloud"}
          onClick={() => setTab("cloud")}
          className={`cs-segment${tab === "cloud" ? " cs-segment-active" : ""}`}
        >
          <span>cloud</span>
          <span className="cs-count">{grouped.cloud.length}</span>
        </button>
      </div>

      <div className="network-grid">
        {visible.length === 0 && (
          <p className="muted">no {tab} models available.</p>
        )}
        {visible.map((m) => (
          <ModelCard
            key={m.id}
            model={m}
            isActive={m.id === activeId}
            busy={busy === m.id}
            onInstall={handleInstall}
            onUninstall={handleUninstall}
            onSetActive={handleSetActive}
            onConnect={handleConnect}
          />
        ))}
      </div>
    </section>
  );
}
