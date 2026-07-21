# BRIEF — Agente ENGINE (theyos) · Persistent Panes (E2→E6)

Você acorda SEM contexto. Leia este brief inteiro antes de qualquer ação. Você é um agente EXECUTOR. O arquiteto/revisor é @jovian (que te enviou isto) — ele revisa e faz o gate de TODO PR. Você NÃO mergeia nada.

## Projeto
Soyeht = app de terminal macOS/iOS. O engine Rust `theyos` (ESTE repo) é dono dos PTYs remotos/guest. Feature em construção: **panes persistentes** — o app macOS passa a rodar panes locais de agente (claude/codex/etc.) sob o engine, pra que atualizar/reiniciar o app NÃO mate as conversas. O engine sobrevive ao restart do app (é serviço launchd separado); o app vira viewer que reconecta.

## Estado / o que já existe (NÃO refaça)
- Branch: `feature/local-pty-broker` (você está nele). Já tem a **E1 pronta e spike-provada** (commit `bfbba8e9`): `LocalSpawnSpec`, `start_pty_session_local`, `wire_pty_session`, `PtyManager::start_local/get_local/close_local`, endpoints `POST /api/v1/terminals/local`, `GET /terminals/local/{id}/pty`, `DELETE /terminals/local/{id}`.
- Cargo workspace fica em `admin/rust/` (NÃO na raiz). Package do servidor = `server-rs` (binário `server`). PTY em `admin/rust/terminal-rs/src/pty.rs`; handlers em `admin/rust/server-rs/src/handlers_terminal.rs`.

## Sua TAREFA — implementar E2→E6, um commit + testes por item, nesta ordem:
- **E2 · Replay TAIL:** hoje o reattach WS (`serve_pty_websocket`, handlers_terminal.rs) replaya o log INTEIRO. Mudar pra replayar só o TAIL (~2 MB / últimas ~5000 linhas) + emitir marker `CTL:replay_truncated` quando cortar. Full-replay vira opt-in por query param. Aceite: reattach num log de 50 MB transfere ~2 MB, não 50; subscriber NÃO nasce `Lagged`.
- **E3 · Rotação do conv log:** hoje ao bater `THEYOS_CONV_LOG_MAX_BYTES` (default 500 MiB) o read loop faz `FileTooLarge → sess.close()` e MATA a sessão (pty.rs ~383-395). Trocar por ROTAÇÃO (truncar a metade mais antiga, manter a recente), nunca kill. Aceite: sessão de output pesado roda indefinidamente; teste com cap pequeno (ex. 1 MiB) provando que rotaciona e continua viva.
- **E4 · Robustez do read loop:** `match (&*pty).read() { Ok(0)|Err(_) => break }` (pty.rs ~371) trata QUALQUER erro como EOF — inclusive `EINTR`. Adicionar retry em `ErrorKind::Interrupted`. E adicionar timeout nos `socket.send(...).await` do replay/forward (WS). Aceite: EINTR não encerra a drenagem; teste unitário do retry.
- **E5 · Metadados de sessão:** expor por sessão local: `slaveTTYPath` (o soyeht-mcp mapeia TTY→pane pra inferir remetente), pgid, liveness, cwd. Endpoint `GET /api/v1/terminals/local` (lista) ou campos no create. Aceite: create retorna slaveTTYPath; lista mostra sessões vivas.
- **E6 · Kill escalação TTY-wide:** ao `close_local`, hoje só mata o child direto. Portar do PR #317 (soyeht-ios) a técnica: snapshot de todos os pids no TTY via `proc_listpids(PROC_TTY_ONLY)` + escalação SIGHUP→(2s)SIGTERM→(2s)SIGKILL. Aceite: um filho que ignora HUP/TERM de propósito morre ≤5s após close.

Ferramenta de teste E2E do arquiteto: `/private/tmp/claude-501/-Users-macstudio-Documents-SwiftProjects-iSoyehtTerm/18bbeb09-f344-4706-a646-881b8399d47d/scratchpad/spike_client.py` (roda contra engine scratch em porta própria; use como referência, adapte pra validar E2/E3).

## GUARDRAILS (violar = retrabalho)
1. **NÃO MERGEIE.** Cada tarefa vira commit; ao terminar E2 (e cada seguinte): push do branch, abra PR **DRAFT** no GitHub (soyeht/theyos), e ANEXE uma linha em `/tmp/soyeht-triage/persistent-panes-status.md` no formato `[ENGINE] Ex PRONTO PR #N — <resumo>` (o arquiteto @jovian monitora esse arquivo + o GitHub e faz o gate/merge). NÃO dependa de Soyeht message pra me alcançar (rodo noutra instância).
2. **Disciplina de teste cross-crate:** ao mudar `terminal-rs`, RODE (não só builde) os testes de TODO crate consumidor (`server-rs` etc.) — `cargo test -p terminal-rs -p server-rs`. Grep por testes que fixam o comportamento antigo.
3. **Branch protection do theyos:** 4 required checks. PR precisa passar. Companion-PR (se tocar contrato) no formato `theyos PR #N` (com espaço quebra o gate).
4. **NUNCA** rode/teste contra o engine de PRODUÇÃO (`~/Library/Application Support/Soyeht/engine/theyos-engine`, pid do launchd). Use engine SCRATCH com `ADDR`, `THEYOS_CONVERSATIONS_DIR`, `THEYOS_SQLITE_DB`, `THEYOS_DIR`, `THEYOS_*_RS_BIN` próprios (veja como o spike faz).
5. **Não pise no time mesh:** outros agentes (@alaine, @kaia, @jovian) mexem neste repo. Fique no SEU branch, rebaseie da main, não toque nos PRs deles.
6. **Sem IPs/nomes reais** em código/testes/PR (use `192.0.2.10`, `mac-alpha`, etc.).
7. Trabalhe autônomo (`/goal`), mas PARE e pergunte ao @jovian se: fork arquitetural real, algo exige tocar produção, ou um check required quebra por motivo não-óbvio.

## Diretório
Você está em `/Users/macstudio/soyeht-worktrees/theyos-persistent-panes` (branch `feature/local-pty-broker`). Cargo em `admin/rust/`. Comece pela **E2**.
