import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
// Dev-only proxies for the /models-preview page so a real API key can hit a
// real provider endpoint from the browser without CORS pain. These do NOT
// ship to production — production routes through the theyos host-side proxy
// where the key never reaches the browser in the first place.
var llmProxy = function (target, prefix, replaceWith) { return ({
    target: target,
    changeOrigin: true,
    secure: true,
    rewrite: function (path) { return path.replace(new RegExp("^".concat(prefix)), replaceWith); },
}); };
export default defineConfig({
    plugins: [react()],
    server: {
        port: 5173,
        proxy: {
            "/api": {
                target: "http://localhost:8892",
                changeOrigin: true,
                ws: true,
            },
            // Z.AI Coding Plan (GLM)
            "/llm-test/zai": llmProxy("https://api.z.ai", "/llm-test/zai", "/api/coding/paas/v4"),
            // OpenAI
            "/llm-test/openai": llmProxy("https://api.openai.com", "/llm-test/openai", "/v1"),
            // Anthropic (uses x-api-key + anthropic-version headers, set by client)
            "/llm-test/anthropic": llmProxy("https://api.anthropic.com", "/llm-test/anthropic", "/v1"),
            // DeepSeek — per openclaw docs, base URL is api.deepseek.com without /v1
            "/llm-test/deepseek": llmProxy("https://api.deepseek.com", "/llm-test/deepseek", ""),
            // Moonshot (Kimi)
            "/llm-test/moonshot": llmProxy("https://api.moonshot.ai", "/llm-test/moonshot", "/v1"),
        },
    },
    build: {
        outDir: "../web",
        emptyOutDir: true,
    },
});
