# Fix: clawwork → available

## O que é

- **Stars:** 7954
- **Repositório:** https://github.com/HKUDS/ClawWork
- **Linguagem:** python
- **Descrição:** OpenClaw as Your AI Coworker — AI agents pay for their own tokens and earn income by completing GDPVal tasks, with a React dashboard tracking survival metrics.

## Problema atual

install plan has apt/pip/npm dependency conflict during manual-shell execution. Needs install plan rewrite.

## Objetivo

Fazer `clawwork` passar de `tier: catalog` para `tier: available`.

Um install bem-sucedido significa:
1. O install plan roda sem erro numa VM Ubuntu 24.04 x86_64 (Firecracker)
2. O binário/entry point fica acessível via PATH
3. `soyeht claws-verify clawwork` retorna `VERIFY_OK:clawwork` no canary

## Como trabalhar

1. Leia o manifest atual:
   ```
   claws/manifest.yml  (seção clawwork)
   ```

2. Investigue o repositório upstream:
   ```
   https://github.com/HKUDS/ClawWork
   ```

3. Edite o manifest para corrigir o install plan. Campos principais:
   - `install_template`: pip-package | node-package | cargo-build | go-binary | raw-binary | manual-shell
   - `install:` — bloco com configs do template escolhido
   - `skip_install_reason:` — remover quando corrigir, ou atualizar se confirmar impossível

4. Compile para checar invariantes:
   ```bash
   cd admin/rust && cargo build -p core-rs
   ```

5. Faça o deploy no canary e rode o verify:
   ```bash
   # No devs (ssh <canary-host>):
   git pull origin fix/catalog/clawwork
   sudo soyeht update
   env HOME=/home/dev THEYOS_DIR=/home/dev/theyos \
     THEYOS_IMAGEBUILDER_BIN=/home/dev/theyos/admin/rust/target/release/imagebuilder \
     sudo -u soyeht soyeht claws-verify clawwork
   ```

6. Se passar: mude `tier: catalog` → `tier: available` no manifest e commit.

## Arquivos relevantes

- `claws/manifest.yml` — fonte de verdade (editar aqui)
- `admin/rust/core-rs/src/manifest.rs` — tipos Rust
- `admin/rust/core-rs/src/templates/` — templates de install
- `claws/verify-results.json` — resultado do último verify

## Contexto de infra

- VM: Ubuntu 24.04, x86_64, Firecracker microVM
- SSH install timeout: 1800s (30min)
- O verify roda na máquina canary (host/user configurados via .env), ex: `<canary-host>`
- `cargo build -p core-rs` deve passar antes de qualquer deploy

## Notas

- Se confirmar que é genuinamente impossível (ex: firmware, APK, app desktop),
  atualize `skip_install_reason` com explicação clara e deixe em `catalog`.
- Não force uma solução que não funciona — catalog com razão documentada é
  melhor que available falso.
