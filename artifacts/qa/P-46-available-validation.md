# P-46 — Validação manual dos 19 claws `tier: available`

**Target:** https://<your-host>.<your-tailnet>.ts.net (<canary-host>, canary)
**Iniciado:** 2026-04-14
**Último update:** (em andamento)

## Critério

Mesmo do P-46 supported (pragmático, sem API keys):
**PASS = install OK em /claws (Ready) + binário presente no VM + `<claw> --version` (ou equivalente) retorna coerente.**

Sem daemon soak (maioria das available foram marcadas `available` via install-only verify — `run_cmd: ""` por design).

## Ordem (por estrelas, desc)

nanoclaw → nemoclaw → tinyagi → edgeclaw → claw-empire → clawlet → zeptoclaw → rosclaw → hermitclaw → myclaw → safeclaw → subzeroclaw → xsafeclaw → epsiclaw → geneclaw → shibaclaw → sharpclaw → angel-claw → loki-claw

## Protocolo por claw

1. `/claws` → click Install, poll até Ready.
2. `POST /api/v1/instances` → instância `smoke-<claw>`, claw_type=<claw>, sem AI coding tools.
3. `/terminals` → PTY na instância, rodar:
   ```bash
   which <claw> && <claw> --version
   ```
   (alguns Go claws usam `version` subcommand; alguns manual-shell não têm `--version` flag — aceitar `--help` ou path como proxy.)
4. Screenshot em `artifacts/qa/screenshots/<claw>.png`.
5. `DELETE /api/v1/instances/<id>`.
6. Marcar tabela.

## Check command por claw (extraído de install plans)

Pra claws template-driven (pip/node/cargo/raw-binary), tento `<entry_point> --version`. Pra manual-shell, olho pro que o `manual_script` entrega: shim em `/usr/local/bin/<claw>` que faz `cd /opt/<claw> && exec <runtime> <main>`. Nesses casos PASS = shim existe + diretório `/opt/<claw>` populado; `--version` na maioria não existe (user dispara via shim).

| claw         | stars  | template        | check_cmd (primeira tentativa)                      |
|--------------|-------:|-----------------|-----------------------------------------------------|
| nanoclaw     | 27257  | manual-shell    | ls /opt/nanoclaw/package.json && which nanoclaw     |
| nemoclaw     | 19186  | node-package    | which nemoclaw && nemoclaw --version                |
| tinyagi      |  3507  | node-package    | which tinyagi && tinyagi --version                  |
| edgeclaw     |  1186  | node-package    | which openclaw && openclaw --version                |
| claw-empire  |  1073  | manual-shell    | ls /opt/claw-empire/package.json && which claw-empire |
| clawlet      |   606  | raw-binary      | which clawlet && clawlet --version                  |
| zeptoclaw    |   588  | cargo-build     | which zeptoclaw && zeptoclaw --version              |
| rosclaw      |   480  | manual-shell    | ls /opt/rosclaw/package.json && which rosclaw       |
| hermitclaw   |   319  | manual-shell    | ls /opt/hermitclaw/hermitclaw/main.py && which hermitclaw |
| myclaw       |   262  | manual-shell    | which myclaw-bin && myclaw-bin --help \| head -1    |
| safeclaw     |   130  | pip-package     | which safeclaw && safeclaw --version                |
| subzeroclaw  |   119  | manual-shell    | which subzeroclaw && (subzeroclaw --version \|\| subzeroclaw --help \| head -1) |
| xsafeclaw    |   108  | pip-package     | which xsafeclaw && xsafeclaw --version              |
| epsiclaw     |    45  | manual-shell    | ls /opt/epsiclaw/agent.py && which epsiclaw         |
| geneclaw     |    35  | pip-package     | which nanobot && nanobot --version                  |
| shibaclaw    |    28  | pip-package     | which shibaclaw && shibaclaw --version              |
| sharpclaw    |    22  | raw-binary      | which sharpclaw && sharpclaw --version              |
| angel-claw   |     6  | pip-package     | which angel-claw && angel-claw --version            |
| loki-claw    |     0  | node-package    | which openclaw && openclaw --version                |

> ⚠️ edgeclaw e loki-claw declaram `entry_point: openclaw` — ambas são forks do OpenClaw. Conflito no mesmo VM é tolerável (só uma instância por VM), mas anotar qual build ficou no binário.
> ⚠️ geneclaw declara `entry_point: nanobot` (reusa o runtime do nanobot). Não é bug do manifest — é a natureza do Geneclaw (fork que reusa o binário upstream).

## Tabela de tracking

| claw         | install | binary | version | verdict | notas |
|--------------|:-------:|:------:|:-------:|:-------:|-------|
| nanoclaw     |    ✓    |   ✓    |    ✓    |  PASS   | shim `cd /opt/nanoclaw && npm start`; `nanoclaw@1.2.52` |
| nemoclaw     |    ✗    |   —    |    —    |  FAIL   | npm pkg `nemoclaw@0.1.0` sem `bin`; lib, não CLI. Reclassificar tier:catalog ou corrigir entry_point |
| tinyagi      |    ✗    |   —    |    —    |  FAIL   | npm pkg `tinyagi@0.0.4` sem `bin`; lib, não CLI. Mesma causa de nemoclaw |
| edgeclaw     |    ✓    |   ✓    |    ✓    |  PASS   | após 2 fixes (entry_point + PATH): `OpenClaw 2026.4.14 (323493f)` em `/usr/bin/openclaw` |
| claw-empire  |    ✓    |   ✓    |    ✓    |  PASS   | shim `cd /opt/claw-empire && pnpm start`; package.json 5843 bytes |
| clawlet      |    ✗    |   ✗    |    —    |  FAIL   | upstream só publica `clawlet_Darwin_x86_64.tar.gz` (macOS). Install plan precisa de release Linux — não existe |
| zeptoclaw    |    ✓    |   ✓    |    ✓    |  PASS   | `zeptoclaw 0.9.2` — cargo-build (~11min build, bin em `/root/.cargo/bin/`) |
| rosclaw      |    ✓    |   ✓    |    ✓    |  PASS   | shim `cd /opt/rosclaw && pnpm start`; package.json presente |
| hermitclaw   |    ✓    |   ✓    |    ✓    |  PASS   | shim `cd /opt/hermitclaw && python3 hermitclaw/main.py` |
| myclaw       |    ✓    |   ✓    |    ✓    |  PASS   | Go binary `/usr/local/bin/myclaw-bin`, shim `myclaw-bin gateway`, /opt/myclaw populated |
| safeclaw     |    ✓    |   ✓    |    ✓    |  PASS   | Click CLI; `--help` OK (`SafeClaw — Keeping Your Claw Safe`); sem `--version` próprio |
| subzeroclaw  |    ✓    |   ✓    |    ✓    |  PASS   | `SubZeroClaw — skill-driven agentic runtime`; config `~/.subzeroclaw/config` |
| xsafeclaw    |    ✓    |   ✓    |    ✓    |  PASS   | Click CLI; `--help` OK (`XSafeClaw — Keeping Your Claw Safe`) |
| epsiclaw     |    ✓    |   ✓    |    ✓    |  PASS   | shim `cd /opt/epsiclaw && python3 agent.py` |
| geneclaw     |    ✓    |   ✓    |    ✓    |  PASS   | após fix entry_point: `nanobot v0.1.5.post1` (via `nanobot-ai` pypi pkg) |
| shibaclaw    |    ✓    |   ✓    |    ✓    |  PASS   | `shibaclaw v0.0.31` |
| sharpclaw    |    ✗    |   ✗    |    —    |  FAIL   | upstream só publica `sharpclaw-linux-arm64.zip`, VM é x86_64. Binário incompatível |
| angel-claw   |    ✓    |   ✓    |    ✗    |  FAIL   | libmagic1 adicionado via system_deps (043730f) resolveu 1º crash, mas 2º crash upstream: `neonize` dep com protobuf gencode 7.34.1 × runtime 6.33.6. Reclassificada tier: catalog |
| loki-claw    |    ✓    |   ✓    |    ✓    |  PASS   | após 2 fixes: `OpenClaw 2026.4.14 (323493f)` (npm `openclaw` em `/usr/bin/openclaw`) |

## Resultados por claw

(preenchido conforme progresso)
