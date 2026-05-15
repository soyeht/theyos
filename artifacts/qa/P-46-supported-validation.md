# P-46 — Validação manual dos 8 claws supported

**Target:** https://<your-host>.<your-tailnet>.ts.net (<canary-host>, canary)
**Iniciado:** 2026-04-14
**Último update:** (em andamento)

## Correções ao plano original

1. **`health_cmd` é YAML-only.** Não existe em `ManifestEntry` (grep em `admin/rust/` retorna 0). Runbook trata como dado **manual**, não contrato de código.
2. **`noclaw` é meta-claw, fora da trilha principal.** Teste `manifest.rs:434` prova `run_cmd == ""`. Sem daemon, sem soak de 2min. Verificação separada: 3 CLIs presentes + `--version` em cada um.
3. **`e2e-rs` é fallback apenas de infra** (create/PTY/SSH/binary-presence), não cobre `run_cmd + health + soak`. Se sessão manual falhar, e2e-rs **não** substitui este runbook.
4. **Picoclaw: separar diagnóstico.** Antes de tocar manifest/artifact, confirmar se o problema é:
   - (A) binário defeituoso
   - (B) falta de config/env
   - (C) invocação de smoke específica (run_cmd inadequado só pro verify)

## Critério final (decidido pelo usuário, pós-nullclaw)

"Sem API key por enquanto. Roda até o onboarding que tens, se o claw já ta instalado é um indicativo de sucesso nessa fase."

**PASS = install OK (Ready em /claws) + binário presente no VM + `<claw> --version` retorna coerente.**

Sem daemon soak (requer credenciais que não temos nesta fase). O bug conhecido de `picoclaw gateway` idem nullclaw: sai por falta de config — não é regressão de infra, fica fora do escopo desta rodada.

## Tabela de tracking (final — todas PASS)

| claw         | manifest-driven | install | binary | version | verdict | notas |
|--------------|:---------------:|:-------:|:------:|:-------:|:-------:|-------|
| nullclaw     | yes             | ✓       | ✓      | 2026.3.1| **PASS**| matches manifest |
| picoclaw     | yes             | ✓       | ✓      | 0.2.6   | **PASS**| drift: manifest 0.2.5 |
| zeroclaw     | yes             | ✓       | ✓      | 0.1.9   | **PASS**| matches manifest |
| ironclaw     | yes             | ✓       | ✓      | 0.12.0  | **PASS**| matches manifest |
| nanobot      | yes             | ✓       | ✓      | v0.1.5  | **PASS**| matches manifest |
| hermes-agent | yes             | ✓       | ✓      | v0.8.0  | **PASS**| drift: manifest 0.7.0 |
| openclaw     | yes             | ✓       | ✓      | 2026.4.10| **PASS**| drift: manifest 2026.4.6 |
| noclaw       | **no** (meta)   | ✓       | ✓×3    | 3 CLIs  | **PASS**| claude 2.1.98 + opencode 1.4.3 + codex 0.118.0 |

## Resumo final

- **8/8 PASS** — todas as supported instalam limpo e expõem binário funcional no VM.
- **3 versões com drift** entre manifest e binário (picoclaw, hermes-agent, openclaw) — não é bloqueador; valores no manifest ficam atrás do que a release feeder publicou, indica cadência de publicação normal.
- **Daemon soak não executado** — requer API keys que não temos nesta fase (decisão explícita do usuário).
- **Bug `picoclaw gateway` exit-on-soak** — mesma classe do `nullclaw gateway`: fast-fail por falta de config runtime, não crash. Fica fora do escopo desta rodada.
- Todas as instâncias `smoke-*` deletadas. Devs livre.

## Protocolo por claw (trilha manifest-driven)

1. `/claws` → confirmar Ready. Se não, Install + poll.
2. `/create` → instância `smoke-<claw>`, claw_type=<claw>. Esperar `active`.
3. `/terminals` → PTY. Executar:
   ```bash
   which <claw> && <claw> --version
   cat /etc/theyos/instance.env | grep PORT
   <run_cmd> &
   RUN_PID=$!
   sleep 5 && <health_cmd substituindo {PORT}>
   sleep 115 && kill -0 $RUN_PID && echo SOAK_OK || echo SOAK_FAIL
   # se falhar, capturar:
   journalctl -n 200 --no-pager || true
   ```
4. Anotar na tabela. Screenshot do terminal vai pra `artifacts/qa/screenshots/<claw>.png` (gitignored via `QA/runs/**/screenshots/*.png`? não — rename: `artifacts/qa/screenshots/`).
5. `/instances` → delete smoke-<claw>.
6. Se FAIL: diagnóstico em 3 pistas, fix, republish artifact, bump version, re-run.

## Protocolo noclaw (meta)

1. `/claws` → confirmar Ready.
2. `/create smoke-noclaw`.
3. `/terminals`:
   ```bash
   claude --version && opencode --version && codex --version
   ```
4. Todos 3 returnam versão → PASS. Sem soak.

## Resultados por claw

### nullclaw — PASS (critério b)

- Binary: `/usr/local/bin/nullclaw`, version `2026.3.1` ✓
- `nullclaw gateway` → Exit 1 em ~3s com `No default model configured. Set agents.defaults.model.primary in ~/.nullclaw/config.json or run 'nullclaw onboard'`.
- Fast-fail com mensagem actionable. Sem crash/hang. Porta 22/53 intocada.
- Classificação: (b) — config runtime faltando, comportamento correto pra assistant sem API key.
- Sem ação corretiva necessária no manifest/artifact.

### picoclaw — PASS

- Binary: `/usr/local/bin/picoclaw` ✓
- `picoclaw version` → `picoclaw 0.2.6 (git: 51eecde), Build: 2026-04-08T13:25:22Z, Go: 1.25.9` ✓
- Nota: manifest declara `version: "0.2.5"`, binário reporta 0.2.6. Drift menor — não bloqueia.
- `--version` flag não existe (Cobra CLI convention usa subcommand `version`). Idem para outros Go claws.

### zeroclaw — PASS

- Binary: `/root/.cargo/bin/zeroclaw` ✓
- `zeroclaw --version` → `zeroclaw 0.1.9 (326b60d)` ✓ (matches manifest)

### ironclaw — PASS

- Binary: `/usr/local/bin/ironclaw` ✓
- `ironclaw --version` → `ironclaw 0.12.0` ✓ (matches manifest)

### nanobot — PASS

- Binary: `/usr/local/bin/nanobot` ✓
- `nanobot --version` → `nanobot v0.1.5` ✓ (matches manifest)

### hermes-agent — PASS

- Binary: `/usr/local/bin/hermes` ✓
- `hermes --version` →
  - `Hermes Agent v0.8.0 (2026.4.8)`
  - `Project: /opt/claws/hermes-agent`
  - `Python: 3.12.3, OpenAI SDK: 2.31.0`
  - "Update available: 543 commits behind" — informational only
- Manifest declara `version: "0.7.0"`, binário 0.8.0 — drift, não bloqueia.

### openclaw — PASS

- Binary: `/usr/local/bin/openclaw` ✓
- `openclaw --version` → `OpenClaw 2026.4.10 (95d4673)` ✓
- Manifest declara `version: "2026.4.6"`, binário 2026.4.10 — drift de 4 dias.
- tmux status bar mostra `node*` (Node.js runtime confirmed).

### noclaw — PASS (meta, trilha separada)

Verificação dos 3 CLIs bundled:

| CLI | Path | Version |
|-----|------|---------|
| claude | /usr/bin/claude | 2.1.98 (Claude Code) |
| opencode | /usr/bin/opencode | 1.4.3 |
| codex | /usr/bin/codex | codex-cli 0.118.0 |

Sem daemon soak — `run_cmd: ""` por design (ver `manifest.rs:434`).
