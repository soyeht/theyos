# Feature Specification: Soyeht Onboarding (Casa, primeiro Mac/Linux, paridade backend)

**Feature Branch**: `005-soyeht-onboarding`
**Created**: 2026-05-09
**Status**: Draft
**Input**: User description: "Soyeht onboarding: Caso A Mac primeiro, Caso B iPhone primeiro foco Mac, Linux backend parity"

## Clarifications

### Session 2026-05-09

- Q: Termux (Android user-mode Linux) entra como target Linux do install script? → A: Fora de escopo no v1. Linux v1 = distros systemd-based (Ubuntu, Debian, Fedora, NixOS) em x86_64/arm64. Termux fica como spec separada futura ("mobile self-host") se aparecer demanda.
- Q: Como distribuir o Soyeht no iPhone para os usuários? → A: App Store oficial (já existe versão prévia publicada). Esta entrega = atualização de versão sobre o app existente, passando por App Review normal. Sandbox limits são realidade desde o design.
- Q: Como autenticar o `/bootstrap/teardown` (operação destrutiva que apaga a casa)? → A: Owner biométrico no iPhone. Mac/Linux recebe POST autenticado por assinatura do device cert pessoal do owner; iPhone exige Face ID/Touch ID antes de assinar. Tailnet ACL sozinho é insuficiente (qualquer peer comprometido viraria nuke).

## Overview

A pessoa abre Soyeht (no iPhone, no Mac, ou termina de instalar no Linux) e em **menos de 60 segundos** tem uma "casa" funcionando, com sua identidade criptográfica pessoal sendo preservada para sempre — sem ter visto a palavra `household`, sem ter aberto um terminal, e sem ter digitado uma senha de admin (sudo).

A diretiva fundadora é "**o motor é invisível**": Soyeht é a marca; o que o usuário vê. O componente Rust (engine) que carrega a casa, gera as chaves, fala Bonjour, e responde pareamento — esse componente nunca é nomeado no UI. O usuário não sabe que existe um servidor; ele sabe apenas que sua casa "está pronta", "está acordada", ou "este Mac entrou na sua casa".

A spec cobre dois casos principais (A: Mac primeiro; B: iPhone primeiro com foco em colocar Soyeht no Mac do usuário), mais a **paridade Linux no backend**: o mesmo engine roda em macOS (LaunchAgent per-user, sem sudo) e em Linux (systemd user unit, sem sudo). A experiência pós-install é idêntica nos dois sistemas — ambos publicam Bonjour, ambos respondem aos mesmos endpoints, ambos podem ser "founder" da casa ou "membro" entrando em casa existente.

Cliente GUI nativo Soyeht para Linux fica fora desta spec (futuro). Para esta spec, Linux é "servidor headless controlado pelo Soyeht do iPhone ou pelo SoyehtMac".

## User Scenarios & Testing

### User Story 1 — Carolina cria sua casa no Mac (Priority: P1)

Carolina baixa Soyeht.dmg de soyeht.com, arrasta Soyeht.app para Applications, e abre. Ela vê um carrossel de 5 cards apresentando o produto (Loja Claw, Times de agentes, Claw vira site, Voz, Mac+iPhone juntos). No final do carrossel, a tela transiciona suavemente para *"Vamos preparar seu Mac"*. Em background o app prepara o motor; em alguns segundos aparece *"Como você quer chamar sua casa?"* com placeholder "Casa Carolina". Ela digita o nome e aperta Enter. Aparece uma animação de chave girando enquanto o motor gera a identidade criptográfica. Quando termina, surge um cartão visual com o nome da casa em destaque, ícone do Mac dentro, e ✨ piscando: *"agora vamos adicionar seu iPhone"*. Carolina pega o iPhone, abre Soyeht; uma notificação rica aparece: *"Casa Carolina te chamou. Entrar?"* + Face ID. Bip. Tela do Mac e do iPhone mostram simultaneamente *"Pronto. Sua casa está pronta."* Tempo total: **menos de 60 segundos** desde abrir o .dmg.

**Why this priority**: É o caminho mais comum (usuário Mac novo) e desbloqueia todo o produto. Sem ele, ninguém entra. Owner aprovou esse fluxo como caminho canônico.

**Independent Test**: Pode ser totalmente testado por uma instalação manual num Mac limpo (sem Soyeht prévio) com um iPhone Soyeht instalado, cronometrando do drag-to-Applications até a tela "Sua casa está pronta". Sucesso = sem sudo prompt, sem terminal, < 60s, casa criada e iPhone paireado.

**Acceptance Scenarios**:

1. **Given** Mac novo (Apple Silicon, macOS 14+) sem Soyeht instalado, **When** usuário abre Soyeht.app pela primeira vez vinda do .dmg notarizado, **Then** o motor é instalado como LaunchAgent per-user em `~/Library/LaunchAgents/com.soyeht.engine.plist` sem solicitar senha de admin.
2. **Given** motor recém-instalado em estado uninitialized, **When** o app pergunta "Como você quer chamar sua casa?" e usuário digita "Casa Carolina" + Enter, **Then** o motor gera o keypair EC P-256 da casa no Secure Enclave, persiste o estado, e retorna `hh_id` + URI de pareamento.
3. **Given** casa criada e aguardando primeiro device pessoal, **When** usuário abre Soyeht no iPhone que já está no mesmo Tailnet do Mac, **Then** o iPhone descobre a casa via Bonjour/Tailscale e dispara notificação rica de aprovação com Face ID — sem QR code visível.
4. **Given** iPhone aprova com Face ID, **When** o pareamento completa, **Then** ambos Mac e iPhone mostram simultaneamente "Sua casa está pronta" e o cartão da casa exibe ambos os devices.
5. **Given** todo o flow concluído, **When** medido do drag-to-Applications até "Sua casa está pronta", **Then** o tempo total é menor que 60 segundos.

---

### User Story 2 — Owner adiciona Linux à casa pelo iPhone (Priority: P1)

Owner já tem uma "Sample Home" funcionando (criada via User Story 1 ou 4). Ele liga um Linux mini novo na mesma rede WiFi de casa e roda *uma única linha de instalação* no terminal do Linux: `curl -fsSL theyos.com/install | sh`. O script copia o motor para `~/.local/share/Soyeht/`, cria uma systemd user unit em `~/.config/systemd/user/soyeht-engine.service`, sobe o motor — tudo sem sudo. O motor sobe em estado uninitialized e começa a publicar Bonjour anunciando "máquina sem casa esperando convite". Em paralelo, no iPhone do Owner (já paireado à Sample Home), aparece automaticamente uma notificação: *"Vimos um Linux novo na sua rede. Adicionar à Sample Home?"* + um "código de segurança" de 6 emoji-palavras. A mesma sequência de emojis aparece no terminal do Linux. Owner bate visualmente — confere — e toca confirmar com Face ID. O Linux entra na Sample Home. O terminal do Linux mostra *"Pronto. Você está dentro da Sample Home."* e fica disponível como máquina-membro para rodar agentes.

**Why this priority**: É o caso de uso self-host puro que diferencia Soyeht de produtos puramente Apple-ecosystem. Adicionar Linux pelo iPhone, sem o usuário tocar no teclado da máquina-alvo após uma única curl, é Apple-grade self-host. Owner identificou esse fluxo como tão importante quanto o User Story 1.

**Independent Test**: Pode ser testado adicionando uma máquina Linux limpa (Ubuntu, Debian, Fedora, NixOS, etc) no mesmo Tailnet de uma casa existente e rodando a curl. Sucesso = single curl sem sudo + Face ID no iPhone + Linux entra no household sem o usuário ter visto QR ou ter digitado nada após a curl.

**Acceptance Scenarios**:

1. **Given** Linux limpo (sem Soyeht) no mesmo Tailnet de uma casa existente, **When** usuário roda `curl -fsSL theyos.com/install | sh`, **Then** o instalador baixa o engine, instala em `~/.local/share/Soyeht/`, cria systemd user unit, e starts o motor sem solicitar sudo nenhuma vez.
2. **Given** motor Linux subindo em estado uninitialized, **When** detecta que está num Tailnet com casa existente publicada via Bonjour, **Then** publica anúncio Bonjour `_soyeht-setup._tcp.` sinalizando "máquina aguardando convite".
3. **Given** Soyeht no iPhone do owner abre ou fica aberto, **When** detecta o anúncio Bonjour da máquina Linux nova, **Then** dispara notificação rica perguntando "Adicionar à Sample Home?" com código de segurança visual.
4. **Given** notificação rica no iPhone, **When** usuário confirma com Face ID, **Then** o iPhone executa a sequência de pareamento (anchor-handoff via Tailnet, sem QR scan visível) e o Linux passa para estado `ready` como membro da casa.
5. **Given** Linux entra como membro, **When** verificado no SoyehtMac ou no iPhone, **Then** o Linux aparece na lista de máquinas da casa, com platform=linux, hostname, e capacidade de rodar claws.

---

### User Story 3 — iPhone primeiro, depois Mac (Caso B) (Priority: P2)

Carolina baixa Soyeht no App Store (futuro) ou TestFlight (interim) **antes** de ter qualquer Mac com Soyeht. Abre, vê o carrossel de 5 cards. Ao final, o app pergunta: *"Onde você quer instalar Soyeht? Você precisa de um Mac (ou Linux) pra ter sua casa — é onde seus agentes vão morar."* com botões: "Tenho um Mac aqui do meu lado", "Tenho um Linux" (disabled nesta rodada — "em breve"), "Pegar o link depois". Ela toca "Tenho um Mac aqui". O iPhone usa AirDrop nativo para mandar Soyeht.dmg ao Mac próximo (mesmo iCloud / Bluetooth). O Mac recebe o popup nativo do macOS aceitando o arquivo. Carolina arrasta Soyeht.app pra Applications e abre. O app, ao subir pela primeira vez, descobre via Bonjour `_soyeht-setup._tcp.` que o iPhone está esperando — pula direto pra fase de criar casa. **A pergunta "qual o nome da casa?" aparece NO iPhone** (teclado já na mão dela), Mac mostra apenas a animação de chave nascendo. Final: ambos os devices mostram simultaneamente "Pronto. Casa Carolina criada."

**Why this priority**: É o caminho de aquisição via mobile — pessoa descobre Soyeht no iPhone (App Store, recomendação social), instala lá primeiro, e o app guia ela a colocar Soyeht no Mac. Importância P2 porque Caso A (Mac primeiro) é mais comum em usuários power; mas Caso B reforça a inversão "iPhone é a identidade".

**Independent Test**: iPhone limpo + Mac limpo, ambos no mesmo Apple ID, ambos próximos. Mede do "tap em Soyeht no App Store" até "Sua casa está pronta" — alvo < 90 segundos (mais que Caso A porque envolve transferência AirDrop).

**Acceptance Scenarios**:

1. **Given** Soyeht instalado no iPhone, sem casa, sem Mac com Soyeht, **When** usuário termina o carrossel e seleciona "Tenho um Mac aqui", **Then** o iPhone aciona AirDrop nativo enviando Soyeht.dmg para Macs próximos do mesmo Apple ID.
2. **Given** AirDrop aceito no Mac e Soyeht.dmg baixado, **When** usuário arrasta Soyeht.app pra Applications e abre, **Then** o app detecta via Bonjour `_soyeht-setup._tcp.` que o iPhone está esperando e pula a tela "Vamos preparar seu Mac" pra ir direto pra "detectei seu iPhone aqui do lado, continuar?"
3. **Given** Mac e iPhone reconhecidos mutuamente, **When** o iPhone exibe "Como você quer chamar sua casa?" (em vez do Mac), **Then** o usuário digita o nome no iPhone (teclado virtual já na mão).
4. **Given** nome digitado no iPhone, **When** o iPhone faz POST `/bootstrap/initialize` no Mac via Tailnet/Bonjour, **Then** o Mac gera o keypair, persiste, e retorna confirmação; ambos os devices mostram o cartão da casa pronta.
5. **Given** AirDrop falha ou indisponível, **When** o iPhone detecta a falha, **Then** mostra fallback elegante: URL `soyeht.com` em fonte gigante + QR-code do mesmo URL, instrução "abra esse endereço no seu Mac, Soyeht continua de onde a gente parou".

---

### User Story 4 — Linux como primeira máquina (founder-Linux) (Priority: P2)

Owner, dev, não tem Mac. Tem iPhone e um Linux mini que quer usar como servidor 24/7 para Soyeht. Roda `curl -fsSL theyos.com/install | sh` no Linux. Instalador baixa motor, cria systemd user unit, sobe motor em estado uninitialized. Owner abre Soyeht no iPhone — descobre o Linux via Bonjour `_soyeht-setup._tcp.`. iPhone pergunta *"Você quer começar uma casa neste Linux?"* (com nome do Linux que descobriu via TXT). Owner toca "Sim". iPhone exibe *"Como você quer chamar sua casa?"*; ele digita "Sample Home". iPhone faz POST `/bootstrap/initialize` no Linux com o nome. Linux gera keypair EC P-256 (no kernel keyring). iPhone vira primeiro device pessoal da Sample Home. Linux é o "primeiro Mac/Linux" (founder) da casa.

**Why this priority**: Para dar paridade ao usuário pure-Linux. Equivalente arquitetural ao User Story 1 (Carolina+Mac), com Linux+iPhone. Owner quer a UX igual: "ambos têm que ser 'sem dor, just works'".

**Independent Test**: Linux limpo (sem casa) + iPhone (sem casa) no mesmo Tailnet ou LAN. Mede do "rodou curl" até "Sample Home criada" no iPhone. Alvo < 90s.

**Acceptance Scenarios**:

1. **Given** Linux fresh sem casa + iPhone com Soyeht sem casa, mesmo Tailnet, **When** usuário roda curl no Linux, **Then** motor sobe em estado uninitialized e publica `_soyeht-setup._tcp.` Bonjour anunciando-se como "máquina sem casa".
2. **Given** Soyeht no iPhone aberto, **When** detecta o Linux pelo Bonjour, **Then** mostra opção "Você quer começar uma casa neste Linux?" com hostname do Linux destacado.
3. **Given** usuário toca "Sim", **When** iPhone pergunta o nome da casa e usuário digita, **Then** iPhone faz POST `/bootstrap/initialize {name}` no Linux via Tailnet.
4. **Given** Linux recebe initialize, **When** gera keypair no kernel keyring + persiste estado, **Then** retorna `hh_id` e disponibiliza `pair_qr_uri`; iPhone executa pareamento auto via anchor-handoff.
5. **Given** pareamento conclui, **When** iPhone mostra "Sample Home criada", **Then** Linux está em estado `ready`, owner-paireado, e pode receber outras máquinas como membros depois.

---

### User Story 5 — Adicionar segundo Mac à casa existente (Priority: P3)

Owner já tem Sample Home rodando (em Linux ou Mac). Compra um Mac mini novo. Liga, baixa Soyeht.dmg, instala, abre Soyeht.app. App detecta via Bonjour/Tailnet que existe Sample Home na rede dele. Mostra: *"Encontramos 'Sample Home' nesta rede. Adicionar este Mac?"* com botão grande. Owner clica. iPhone vibra com notificação rica perguntando confirmação + código de segurança visual. Face ID. Mac mini entra na Sample Home como membro.

**Why this priority**: É o segundo-Mac scenario que Owner levantou explicitamente. P3 porque é um cenário menos frequente que primeira-instalação, mas validar isso confirma que a arquitetura da casa suporta multi-machine.

**Independent Test**: Casa pré-existente + Mac novo no mesmo Tailnet. Verifica que sem perguntas de "novo vs juntar" o app já oferece "adicionar à Sample Home".

**Acceptance Scenarios**:

1. **Given** Sample Home existe em outra máquina (Mac ou Linux) no Tailnet do usuário, **When** novo Mac instala Soyeht.app e abre, **Then** o app, durante os 3 segundos de "respiração inicial", descobre Sample Home via Bonjour Tailnet enriquecido (TXT contém `hh_name="Sample Home"`, `device_count=2`, etc.).
2. **Given** descoberta succeeded, **When** o app exibe a tela inicial pós-carrossel, **Then** mostra "Encontramos 'Sample Home' nesta rede" com botão grande "Adicionar este Mac" e link discreto "Configurar do zero".
3. **Given** usuário clica "Adicionar este Mac", **When** Mac novo executa o flow de candidate-join via anchor-handoff sobre Tailnet, **Then** iPhone do Owner recebe notificação de confirmação biométrica.
4. **Given** Owner aprova com Face ID, **When** anchor-handoff + finalize completam, **Then** novo Mac entra como membro da Sample Home (não cria casa nova) e aparece no SoyehtMac do Owner listando as máquinas.

---

### Edge Cases

- **Tailscale offline / não instalado**: Auto-discovery via Tailnet falha. App degrada graciosamente: mostra opção manual "Já tenho Soyeht em outro Mac/Linux na mesma rede local" → busca por Bonjour LAN bruta com aviso de segurança. Se LAN também falha, "Configurar do zero" como path único.
- **iPhone fora de alcance / sem internet**: Mac não consegue completar o pareamento. Tela mostra retry com timeout 2 minutos, depois cai para "Continuar sem iPhone agora — você pode adicionar mais tarde".
- **Código de segurança de 6 emoji-palavras NÃO bate** entre Mac e iPhone: usuário toca "não bate" no iPhone; flow aborta + alerta "algo errado, tente de novo". Phase 3 anchor é re-mintado, novo código gerado, retry.
- **Motor falha ao bindar :8091/:8892** (porta ocupada): app detecta erro via `/bootstrap/status` retornando estado falho; mostra mensagem clara "outra app está ocupando a porta, encerre [com lista]" sem expor detalhes técnicos.
- **Disk cheio durante install**: instalador detecta antes de copiar binário, alerta usuário com espaço necessário, aborta atomicamente sem deixar lixo.
- **Notarização inválida (Gatekeeper)**: macOS bloqueia abertura. Site soyeht.com tem instruções "Abrir Preferências → Privacidade → Permitir mesmo assim" se aparecer dialog quarantine.
- **Linux distro sem systemd user**: install falha graciosamente com mensagem "este sistema não suporta systemd user mode; veja docs/manual-install.md". (NixOS específico tem path próprio via flake module.)
- **Linux sem `loginctl enable-linger`**: motor cai quando user desloga. Instalador detecta e oferece habilitar linger (single comando, sem sudo se rootless config permitir, ou com sudo se preciso — único momento onde sudo aparece, e claramente justificado).
- **Múltiplas casas detectadas no Tailnet** (ex: usuário tem casa pessoal + casa de trabalho): app mostra lista e usuário escolhe. Se filtro de confiança não confia em alguma, omite.
- **Casa detectada na LAN mas não no Tailnet** (ex: outra pessoa na mesma rede WiFi): NÃO sugere automaticamente. Aparece só se usuário explicitamente acionar "buscar na rede local".
- **Usuário tenta criar duas casas no mesmo iPhone**: bloqueia com mensagem "Você já tem 'Sample Home'. Para criar uma casa diferente, restaure este iPhone primeiro ou use outro device."
- **Primeira execução em Mac multi-user**: cada user account tem sua própria casa (LaunchAgent é per-user). Casas não se misturam mesmo no mesmo hardware.
- **Disco encriptado mas Secure Enclave não disponível** (Macs antigos): cair para keystore software-fallback (Phase 3 carve-out já existe — `THEYOS_FORCE_SOFTWARE_KEYS=1`); aviso discreto "este Mac não suporta nosso modo seguro recomendado".
- **Sparkle update detecta versão nova durante uso**: prompt opcional "atualização disponível, reiniciar agora?" ou em background no próximo restart.

## Requirements *(mandatory)*

### Functional Requirements

#### Engine bootstrap state machine

- **FR-001**: O engine MUST sair de boot em estado `uninitialized` (sem chave, sem casa, sem nome), com listeners HTTP up nas portas configuradas, esperando comando do app cliente.
- **FR-002**: O engine MUST expor `GET /bootstrap/status` retornando JSON `{state, version, platform, host_label}` onde `state` ∈ {`uninitialized`, `ready_for_naming`, `named_awaiting_pair`, `ready`, `recovering`}.
- **FR-003**: O engine MUST aceitar `POST /bootstrap/initialize {name}` apenas em estado `uninitialized` ou `ready_for_naming`; mintar `(hh_priv, hh_pub)` EC P-256 no Secure Enclave (macOS) ou kernel keyring (Linux); persistir `household-state/` atomicamente; transitar pra `named_awaiting_pair`; retornar `{hh_id, hh_pub, pair_qr_uri}`.
- **FR-004**: O engine MUST aceitar `POST /bootstrap/teardown` em qualquer estado, mas SOMENTE quando o request carrega assinatura válida do device cert pessoal do owner (Phase 2). O iPhone do owner exige Face ID/Touch ID antes de gerar essa assinatura. Tailnet ACL sozinho NÃO é suficiente. Após autenticação válida, remover `household-state/` atomicamente; voltar pra `uninitialized`.
- **FR-005**: O engine MUST aceitar `POST /bootstrap/claim-setup-invitation {token}` em estado `uninitialized`; verificar token via lookup ao endpoint efêmero do iPhone (autenticado pelo próprio token); marcar engine como "iniciado-pelo-iPhone" para o app cliente reconhecer.
- **FR-006**: O engine MUST expor `GET /pair-machine/anchor-handoff` (autenticado por Tailscale ACL — endpoint só responde a peers no mesmo tailnet) entregando `anchor_secret` direto ao iPhone-cliente, eliminando a necessidade de QR scan no fluxo auto-pair.
- **FR-007**: O engine MUST suportar transição `ready` → `recovering` quando recebe um pedido de recovery (perda de iPhone) — operação fora-de-escopo desta spec mas o estado deve estar reservado.

#### Engine portability + bundling

- **FR-008**: O engine binary MUST ser portátil — sem dependências de brew, systemd, ou nix presentes no environment do usuário; lê apenas variáveis de ambiente bem-definidas (`THEYOS_DIR`, `THEYOS_HOUSEHOLD_PORT`).
- **FR-009**: No macOS, o engine MUST poder ser bundleado dentro de Soyeht.app em `Contents/Helpers/soyeht-engine` e iniciado como LaunchAgent per-user com plist em `~/Library/LaunchAgents/com.soyeht.engine.plist`. **Sem necessidade de sudo** em qualquer ponto.
- **FR-010**: No Linux, o engine MUST ser instalável via single curl pipe que copia binário para `~/.local/share/Soyeht/`, drop systemd user unit em `~/.config/systemd/user/soyeht-engine.service`, e inicia com `systemctl --user start`. **Sem necessidade de sudo**.
- **FR-011**: O state dir MUST resolver para `~/Library/Application Support/Soyeht/` no macOS e `$XDG_DATA_HOME/Soyeht/` (ou `~/.local/share/Soyeht/`) no Linux por default; envvar `THEYOS_DIR` override mantido pra dev/test.

#### Bonjour discovery enrichment

- **FR-012**: Todo motor que está em estado `ready` MUST publicar service `_soyeht-household._tcp.` com TXT incluindo: `hh_id`, `hh_name`, `owner_display_name`, `device_count`, `platform` (macos/linux), `bootstrap_state`, e os campos já existentes do contrato Bonjour (Phase 2/3).
- **FR-013**: Todo motor que está em estado `uninitialized` ou `named_awaiting_pair` MUST publicar service `_soyeht-setup._tcp.` com TXT `{platform, host_label, version, token?}` para que apps clientes na mesma rede ofereçam onboarding automático.
- **FR-014**: O publisher Bonjour MUST funcionar em macOS (via FFI direto a `dns_sd.h`, conforme PR #42) e em Linux (via Avahi ou implementação portátil); regressão silenciosa em multi-interface NÃO é aceitável (lição aprendida do bug T046 corrigido em 2026-05).
- **FR-015**: O browser Bonjour do app cliente (SoyehtMac, Soyeht iPhone) MUST filtrar resultados por **Tailnet trust** por default — só sugerir casas/setups que estejam no Tailnet do usuário. LAN bruta é fallback explícito.

#### App-engine handshake

- **FR-016**: SoyehtMac, ao subir pela primeira vez, MUST: (a) verificar se há LaunchAgent + engine rodando local via `GET /health`; (b) se não, copiar engine de `Contents/Helpers/` para `~/Library/Application Support/Soyeht/engine/`, criar plist, `launchctl bootstrap`; (c) pollar `GET /bootstrap/status` até `state == "ready_for_naming"`; (d) renderizar a tela apropriada baseada no estado.
- **FR-017**: O app cliente (Mac ou iPhone) MUST poder navegar entre os 5 estados do engine sem assumir que algum estado já foi atingido — inclusive cobrindo recovery de crash mid-flow (re-poll `/bootstrap/status` ao reabrir).
- **FR-018**: O auto-pair via anchor-handoff MUST eliminar a necessidade de QR scan no caminho comum (Tailnet trust verificado); QR-scan permanece como fallback explícito quando sinais de confiança falham.

#### iOS carousel + iPhone-first flow

- **FR-019**: O Soyeht iPhone MUST exibir um carrossel de 5 cards **apenas na primeira execução**: Loja Claw, Times de agentes, Claw vira site, Voz, Mac+iPhone juntos. Ordem aprovada por Owner. Revival deliberado via Settings → Sobre → "Reapresentar tour" (ato explícito, não toggle on/off).
- **FR-020**: Pós-carrossel, se Soyeht iPhone não está em casa nenhuma, MUST perguntar "Onde você quer instalar Soyeht?" com opções: "Tenho um Mac aqui", "Tenho um Linux" (disabled em rodada inicial), "Pegar o link depois".
- **FR-021**: "Tenho um Mac aqui" MUST acionar AirDrop nativo enviando Soyeht.dmg ao Mac próximo do mesmo Apple ID; em paralelo MUST publicar `_soyeht-setup._tcp.` Bonjour com token efêmero para o Mac descobrir.
- **FR-022**: Quando iPhone publica setup invitation com token, MUST aceitar requests do Mac via Tailnet com proof do mesmo token e responder com `{hh_id, hh_pub}` necessários para o anchor-handoff.

#### Vocabulário e linguagem

- **FR-023**: O UI MUST nunca usar as palavras: `household`, `founder`, `candidate`, `fingerprint`, `anchor`, `pair-machine`, `pair-device`, `hh_pub`, `BIP-39`, `shard`, `Shamir`, `daemon`, `server`, `motor`, `engine`, `theyOS`. (Tradução interna mantida em código.)
- **FR-024**: O UI MUST usar vocabulário **uniforme cross-platform**: `casa`, `primeiro morador` (owner), **`primeiro computador da casa`** (no lugar de "primeiro Mac" / "primeiro Linux" — usuário não diferencia plataforma; same word for Mac, Linux, future), `adicionar máquina` (no lugar de adicionar Mac/Linux specific), `código de segurança` (no lugar de fingerprint), `ativar com iPhone` (no lugar de pair-device), `este computador entrou na sua casa`. Vocabulary canonical: ver iSoyehtTerm/specs/017-onboarding-canonical/spec.md FR-002 como source of truth do glossário user-facing.
- **FR-025**: O "código de segurança" anti-phishing MUST ser apresentado como **6 emoji-palavras** derivadas determinísticamente: algoritmo usa BIP-39 wordlist em **English como input invariant** (lookup table 1-to-1 BIP-39-EN → 2048 emojis Unicode 12 estáveis); display label visual da palavra-emoji é **localizado** (FR-localization-15 abaixo). Clientes mantêm lookup table — fixture cross-language em `specs/005-soyeht-onboarding/contracts/emoji-security-code-fixtures.csv`. Mac e iPhone mostram a mesma sequência lado a lado. **Apresentação visual segue iSoyehtTerm FR-128/FR-129 como source of truth**: staggered animation 60ms apart, glow halo verde sync nos dois devices ao match, haptic FR-114 ambos no momento de confirmação. Algoritmo é minha autoridade; rendering é autoridade do agente-front.
- **FR-026**: A frase "Sua casa é uma identidade criptográfica gerada agora neste Mac. Suas outras máquinas vão entrar nela." MUST aparecer em cinza pequeno na tela de criar casa, comunicando o conceito sem jargão.
- **FR-027**: Mensagem de recuperação MUST aparecer cedo no onboarding (entre criação de casa e primeiro pareamento iPhone): *"Sua casa é protegida pelas suas máquinas. Se um dispositivo se perder, os outros restauram."* Frase visível mas não-bloqueante.
- **FR-027a (localization)**: Soyeht (iPhone + macOS app + engine UI strings) MUST suportar **15 idiomas**: `ar` (Arabic), `bn` (Bengali), `de` (German), `en` (English), `es` (Spanish), `fr` (French), `hi` (Hindi), `id` (Indonesian), `ja` (Japanese), `mr` (Marathi), `pt-BR` (Portuguese Brazil), `pt-PT` (Portuguese Portugal), `ru` (Russian), `te` (Telugu), `ur` (Urdu). RTL layout obrigatório para `ar` e `ur`. Strings via `LocalizedStringResource(key, defaultValue:, comment:)` no Swift e via i18n catalog no engine. **Important para FR-025**: o algoritmo emoji-derivation usa BIP-39 wordlist em English como input invariant (cross-language byte-equal); o display label da palavra-emoji na UI é localizado (cada emoji vem com a tradução do conceito da palavra BIP-39 no idioma do usuário). Locale resolution canonical: ver iSoyehtTerm/specs/017-onboarding-canonical FR-004/FR-005/FR-088/FR-138/FR-139/FR-140 como source of truth pra glossário localizado, plurais, e RTL UI.

#### Distribuição

- **FR-028**: Soyeht.dmg MUST ser distribuído via soyeht.com (ou subdominio análogo), assinado com Developer ID Application (PR #43 estabelecido), notarizado, com Sparkle para auto-update.
- **FR-029**: Linux install script MUST ser servido em `https://theyos.com/install` (ou análogo) como shell script idempotente, **com checksum verificável** (curl deve permitir validação fácil — script publica seu próprio sha256 no header do arquivo; documentação mostra `curl -fsSL theyos.com/install | tee /tmp/install.sh && sha256sum /tmp/install.sh && sh /tmp/install.sh` como variant explícita pra usuários cuidadosos).
- **FR-030**: Soyeht.app version e engine version MUST ser locked-in-sync — o engine bundleado dentro do .app sempre tem versão exata equivalente ao app. Auto-update via Sparkle atualiza ambos atomicamente.
- **FR-031**: Apple Silicon-only no v1 do macOS; Linux suporta x86_64 e ARM64. Comunicação de requisitos clara em soyeht.com.

#### Telemetria

- **FR-032**: Telemetria MUST ser opt-in com prompt único durante carrossel ou primeira tela: "Aceita compartilhar dados anônimos de uso pra ajudar a melhorar?" + toggle visível em Settings.
- **FR-033**: Eventos rastreados MUST ser limitados a uma enumeração fechada: `install.started`, `install.completed`, `install.failed{error_class}`, `first_pair.completed`, `first_pair.failed{error_class}`, `casa_created`, `device_added`, etc.
- **FR-034**: `error_class` MUST ser enum fechado (ex: `DAEMON_BIND_FAILED`, `KEYCHAIN_ACL_DENIED`, `BONJOUR_PUBLISH_TIMEOUT`, `TAILSCALE_NOT_RUNNING`); strings livres NUNCA enviadas.
- **FR-035**: PII (hostname, IPs, usernames, file paths) MUST ser strippada client-side antes de enviar; device-ID enviado apenas como hash (SHA-256) sem reversibilidade.
- **FR-036**: Endpoint de telemetria MUST ser próprio (`https://telemetry.soyeht.com`), não terceiros (Mixpanel, Segment, etc.).

#### Casos especiais Linux

- **FR-037**: NixOS install path MUST ser ortogonal ao curl install script — usuário NixOS pode optar por uma flake module oficial Soyeht que faz a mesma coisa (drop unit, instala binary), mantendo NixOS reproducibility. Documentação aponta os dois caminhos.
- **FR-038**: Quando Linux instala via curl em distro com firewall ativo (UFW, firewalld), o install script MUST detectar e instruir explicitamente sobre liberar portas necessárias — OU usar apenas tailscale0 (trusted) e não pedir liberação. Decisão fica entre as duas baseado em flag user pode passar.
- **FR-039**: NixOS module oficial MUST abrir as portas necessárias (`8091`, `8892`, ou `cfg.port` configurável) em `networking.firewall.allowedTCPPorts` — bug encontrado durante Story 2 walkthrough fica corrigido nesta entrega.

#### Testabilidade

- **FR-040**: O contract dos endpoints `/bootstrap/*` MUST estar documentado em `specs/005-soyeht-onboarding/contracts/` em arquivos markdown deterministicamente reproduzíveis (CBOR shapes, success/failure responses, ordering rules) — paridade com Phase 2/3 que já fizeram isso.
- **FR-041**: Walkthrough hardware end-to-end MUST cobrir: (a) Caso A em Mac novo, (b) Caso B em iPhone+Mac novos, (c) Linux founder em Linux novo, (d) Linux candidate em Linux novo entrando em casa Mac existente. Cada um cronometrado e gravado em vídeo curto pra documentação.

### Key Entities

- **Casa (household)**: Identidade criptográfica raiz EC P-256 (`hh_priv`/`hh_pub`), nascida no momento de "criar casa". Persiste para sempre. Tem nome amigável dado pelo usuário ("Sample Home"). Membros (Mac, Linux) compartilham essa identidade via certs e shards Shamir; devices pessoais (iPhone, Apple Watch futuro) entram via owner-pairing.
- **Máquina (Mac/Linux)**: Hardware que hospeda agentes (claws). Hospeda também o engine. Tem sua própria identidade `(m_priv, m_pub)`, é membro de uma casa. Pode ser founder (criou a casa) ou member (entrou depois).
- **Device pessoal (iPhone)**: Dispositivo pessoal do owner. Tem cert assinado pela casa. Pode aprovar adições de novas máquinas, recuperar casa em caso de perda.
- **Convite de setup (Setup Invitation)**: Token efêmero (32 bytes, TTL 1h) gerado pelo iPhone quando inicia AirDrop install no Mac. Permite que o motor recém-instalado no Mac reconheça que está numa instalação iniciada-pelo-iPhone.
- **Anchor secret**: 32 bytes mintados no setup time da máquina candidate, transportados ou via QR scan (fallback) ou via anchor-handoff endpoint (auto-pair sobre Tailnet). Authenticator que prova ao iPhone que está realmente falando com a máquina certa.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Caso A (Mac primeiro) — usuário completa do "drag-to-Applications" até "Sua casa está pronta" em **menos de 60 segundos** em hardware típico (M1 ou superior, conexão WiFi/Tailnet 50+ Mbps).
- **SC-002**: Caso B (iPhone primeiro) — usuário completa do "tap em Soyeht na App Store" até "Sua casa está pronta" em **menos de 90 segundos** quando AirDrop disponível; **menos de 180 segundos** em fallback URL+download.
- **SC-003**: Linux candidate add (User Story 2) — após o curl no Linux, "Linux entra na casa" em **menos de 30 segundos**.
- **SC-004**: **Zero sudo prompts** no fluxo Mac do início ao fim. Linux: zero sudo no install padrão; sudo só aparece se usuário escolher caminho avançado de firewall ou linger explícito.
- **SC-005**: **Zero comandos terminal** no fluxo Mac do início ao fim. Linux: máximo de 1 comando (curl single-line).
- **SC-006**: Bundle Soyeht.app+engine ship atomicamente: 100% das atualizações via Sparkle não causam version skew (zero ocorrências de "engine v0.x mas app v0.y" — eliminada a classe de bug que sofremos no v0.1.6/0.1.7/0.1.8).
- **SC-007**: 95%+ dos pareamentos no caminho comum (Tailnet ativo) acontecem **sem QR scan visível** — auto-pair via anchor-handoff. QR scan aparece somente em fallbacks (Tailnet offline, etc.).
- **SC-008**: Zero ocorrências de palavra técnica banida (FR-023) em strings de UI (validado por audit automatizado em CI antes de release).
- **SC-009**: Mensagem de recuperação ("Sua casa é protegida pelas suas máquinas...") visível em pelo menos 1 tela do onboarding inicial — verificado em screenshots de QA.
- **SC-010**: Telemetria opt-in: prompt aparece exatamente **uma vez** na vida do usuário; default Sim/Não é tunable em CI antes de ship; opt-out é one-click em Settings.
- **SC-011**: Bonjour publishing funciona em macOS multi-interface (regressão T046 não retorna): teste de smoke `bonjour_macos_smoke.rs` mantém-se verde no CI cross-version.
- **SC-012**: Recovery scenario (perda de iPhone, restauração via outro Mac/Linux da casa) funcionalmente possível — documentado em runbook mas full-flow UX é fora do escopo desta spec.

## Assumptions

- **A01**: Apple Silicon-only no Mac no v1. Macs Intel ficam fora — release notes claras.
- **A02**: macOS 14+ (Sonoma) — alinhado com requisito atual de VZ Framework e codesign Developer ID modernos.
- **A03**: Linux com kernel 5.x+ e systemd. Distros sem systemd (Alpine OpenRC, Devuan, etc.) ficam fora do path padrão; manual install possível mas não suportado.
- **A04**: Tailscale instalado e ativo é o caminho de "rede confiável" assumido. Sem Tailscale, fallback é LAN bruta com aviso de segurança ou QR-scan manual. Tailscale install em si NÃO é parte deste spec (usuário precisa ter Tailscale up; Soyeht oferece dica para instalar mas não automatiza).
- **A05**: iPhone 11+ com iOS 16+. Versões mais antigas não testadas.
- **A06**: O Soyeht iPhone v1 já está publicado no App Store oficial (versão anterior). Esta spec é entregue como atualização do app existente passando por App Review normal. Sandbox limits do iOS App Store são realidade desde o design — entitlements novos (Bonjour, NWBrowser, AirDrop, Local Network usage) precisam estar declarados no Info.plist com justificativa para review.
- **A07**: O engine compartilha 80%+ de código entre macOS e Linux (`server-rs` workspace). Diferenças de plataforma estão isoladas em `cfg(target_os)` blocks bem-delimitados.
- **A08**: O usuário tem **uma única casa** ativa por device pessoal (iPhone, Apple Watch). Multi-tenant scenarios (várias casas separadas no mesmo iPhone) ficam fora.
- **A09**: O migration path de usuários existentes (que rodam `brew install theyos` hoje) será coberto em spec separada (006-migration). Esta spec assume usuários greenfield.
- **A10**: Soyeht GUI app para Linux (futuro) ficará fora desta spec. Linux v1 é "servidor headless controlado pelo Soyeht do iPhone ou pelo SoyehtMac".
- **A11**: Sparkle framework é a escolha pra auto-update no macOS. Avaliação de alternativas (custom updater, App Store delivery) fica em spec separada se for revisitar.
- **A12**: Endpoint `https://telemetry.soyeht.com` é Cloudflare Worker que registra eventos e zero PII; infrastructure dele é fora do escopo desta spec mas presumida existir antes de ship.

## Open Questions

*(All open questions from the initial draft were resolved in the 2026-05-09 clarify session — see "Clarifications" near the top of this document.)*

## Dependencies

- **D01**: PR #42 mdns-sd publisher fix (merged) — pré-requisito para Bonjour funcionar em macOS multi-interface.
- **D02**: PR #43 Developer ID code-signing (merged) — pré-requisito para distribuir Soyeht.dmg notarizado.
- **D03**: PR #50 NixOS dbus buildInput (merged) — pré-requisito para Linux NixOS install funcionar.
- **D04**: Phase 2 owner-pairing (Story 1) hardware-validated — base para o flow "iPhone scaneia QR" como fallback.
- **D05**: Phase 3 machine-join (Story 2) protocol — base para anchor-handoff (que substitui o QR scan no auto-pair).
- **D06**: Tailscale presence + ACL config no Tailnet do usuário — exógeno mas necessário para auto-discovery seguro.
