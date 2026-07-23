# Derivada DP2 — PendingFinished de PRODUÇÃO + ponte A2 (v1.2 — RE-PERSISTÊNCIA)

Autora: safia · 2026-07-23 · por autorização direta do Caio (bloco 2026-07-23, item 3) e
despacho Prioridade-1 da kiana.

## Proveniência v1.2 (todas as mudanças desta versão estão NESTE bloco; nada abaixo do
## delimitador foi alterado)

- O conteúdo abaixo do delimitador é a **v1.1-final RECUPERADA de file-history e
  verificada por hash**: raw SHA-256
  `db6ecf3705559a6ef05abade064a28af52257dcf7266b599d4d2ddfe209dfa61` · 24567 bytes ·
  357 linhas. VERIFICAÇÃO MECÂNICA: remova este cabeçalho até (e incluindo) a linha
  delimitadora `=====BEGIN v1.1-final (bytes verbatim)=====` e o newline que a segue;
  o restante deve hashear EXATAMENTE para o SHA acima.
- Diferente do contrato-pai (bytes irrecuperáveis, re-emitido como v2), AQUI os bytes
  existem e são verificáveis — esta v1.2 é re-persistência de conteúdo íntegro com NOVA
  identidade versionada; não há reconstrução de memória.
- **Re-anchoragem de referência (única mudança semântica, feita AQUI no cabeçalho, não no
  corpo):** onde o §0 abaixo cita `owner-site-a2-data-plane-security-contract-2026-07-16.md`
  (o "contrato-fonte" v1, perdido), a referência passa a resolver para
  `owner-site-a2-data-plane-security-contract-v2.md` (a RE-EMISSÃO v2, tripla de freeze no
  registro de emissão). A regra de conflito do §0 (vence a MAIS RESTRITIVA) permanece.
  NOTA: o §5.1 citado abaixo ("os 7 rechecks") resolve para a lista RE-DERIVADA do v2 §5.1
  — cânone novo, não o literal v1 perdido.
- Ratificação: NÃO auto-ratificado; vincula após re-read funcional (adriana) + landing
  (kiana) + freeze SHA-bound in-repo. Os re-GOs históricos da v1.1 (jovian arquitetura +
  adriana funcional, sobre os bytes substantivos) referem-se ao conteúdo abaixo, que está
  byte-preservado; a re-ratificação v1.2 confirma a RE-ANCHORAGEM, não reabre o conteúdo.

=====BEGIN v1.1-final (bytes verbatim)=====
# Contrato normativo — PendingFinished de PRODUÇÃO + ponte A2 como prova tipada de canal (v1.1-final)

Autora: @safia · 2026-07-17 · POR DESIGNAÇÃO da @kiana após decisão do Caio
(DP-A + R1-A). **ESTADO: v1.1-final — NORMA VINCULANTE. Re-revisão dupla FECHADA
sobre o conteúdo substantivo (bytes 8e9f27d5): @jovian re-GO de arquitetura +
@adriana re-GO funcional + Fatia-1-intacta, ambos verificados direto no arquivo
(não paráfrase); @kiana coordenou. NÃO auto-ratificado.** SUCEDE e CORRIGE a
v1-final (raw SHA-256 629ce978), que tinha DOIS erros pegos na re-revisão/impl:
(1) MÉTRICA de count — o guard #367 afere `VerifiedMeshPeer(`/`DialPermit(` ==
**1** em owner_site_promotion.rs (as DECLARAÇÕES tuple-struct), não ==0; o
contrato dizia "count==0 nos dois módulos", falso e contraditório com "byte-
intacto". Corrigido: ZERO CONSTRUÇÕES além das declarações → promotion prova por
BYTE-INTACTO (string-match ==1 preservado), authority por count LITERAL ==0.
(2) CONFLAÇÃO autorização-vs-expressão em A.6.2/A.6.3 — "construção só no
linearizador" é impossível em Rust (seal privado a owner_site_promotion → a
expressão vive lá). Corrigido: autorização exclusiva do linearizador via witness;
expressão substitui o CORPO do único promote() (pub(crate) fn ==1 estável, count
1→2). Raízes assumidas (ambas classe paráfrase/inferência-vs-fonte): eu confiei
no "==0" do grounding sem ler o `assert_eq`; a conflação inferia sem a semântica
do seal. O gate em camadas (impl-time da @alaine, depois re-revisão) pegou os
dois. O status foi reconciliado para FINAL só no header/§5 APÓS os dois re-GOs; o
conteúdo revisado (bytes 8e9f27d5) não mudou. NÃO é código nem diretiva — é a NORMA. verificador ≠
autor no nível de IMPL (autoro a norma, verifico o código da @alaine contra ela).

## 0. Norma-pai e regra de conflito
Estende `owner-site-a2-data-plane-security-contract-2026-07-16.md` (o
"contrato-fonte"), que permanece autoritativo. Em conflito, vence a regra MAIS
RESTRITIVA (contrato-fonte §1). Este documento CONCRETIZA duas peças que o
contrato-fonte descreve em design mas que hoje NÃO existem em produção:
- **DP-A:** o `PendingFinished` de PRODUÇÃO (hoje só existe um em
  `#[cfg(test)] mod harness`, owner_site_ake.rs:103–3292; NÃO é produção).
- **R1-A:** a sessão A2 owner-present como PROVA TIPADA de canal autenticado E
  confidencial, satisfazendo o fail-closed do R2 do R0b (o meu D1) — o canal de
  distribuição do rendezvous-id da peça 5.
Ambos foram acoplados pelo Caio numa decisão; este contrato os fecha juntos.

## 1. Estado de base VERIFICADO (origin/main 50b7e3d8, fetch fresco)
- PRODUÇÃO/existe (deny-only, #367): `owner_site_promotion.rs` tem
  `VerifiedMeshPeer(VerifiedMeshPeerSeal)`, `DialPermit(DialPermitSeal)`,
  `OwnerSitePromotedChannel{peer,permit}`, `OwnerSitePromotionRequest(...Seal)`,
  todos `#[derive(Debug,Eq,PartialEq)]` (SEM Serialize/Clone/Deserialize/Default),
  seal privado, doc pina "no production constructor". Contrato de teste em
  `claw_store_contract.rs` pina a forma.
- TEST-HARNESS/NÃO-produção: `OwnerSiteAkePendingFinished` + `recheck_pending_finished`
  (dentro do `#[cfg(test)] mod harness`). O harness Pending tem UM campo
  `generation`, não os DOIS (provider + cancellation) do tuplo §3.
- Este contrato: EXTENDE os carriers de promoção existentes; CRIA o Pending de
  produção; NÃO enfraquece o contrato de teste deny-only (só fortalece).

## PARTE A — PendingFinished de PRODUÇÃO (DP-A)

### A.1 Tipo selado, tuplo §3 COMPLETO, posse
`PendingFinished` de produção é tipo NOVO, selado, irmão (não alias) dos
carriers de #367. Incorpora o tuplo imutável §3 COMPLETO (15 campos), com AS
DUAS gerações separadas — corrige o harness que só tinha uma:
```
(household, recurso_exato, rota_exata, machine_cert, device_binding,
 principal_D, ws_instance, channel_id, channel_epoch, CB, authz_epoch,
 roster_digest, fresh_until, provider_generation, cancellation_generation)
```
Regras de posse (vinculantes; minhas afiações D4 aplicadas ao tipo de produção):
- construtor PRIVADO ao módulo que detém o linearizador; CAMPOS privados (não só
  o construtor — struct-literal de fora não pode mintar);
- SEM `Serialize`, `Clone`, `Deserialize`, `Default`, `From`/`TryFrom` que
  contorne o linearizador (Deserialize é caminho de construção oculto — proibido);
- `Debug` CUSTOM REDIGIDO (o tipo carrega material do tuplo; derive vazaria);
  logs/telemetria/erros não expõem channel/proof/permit;
- tuplo imutável: sem setter, sem `&mut` que faça rebind; divergência ⇒ fechar +
  refazer A2 (contrato-fonte §3), nunca rebind.
Reverse-taint: o `PendingFinished` de produção deve ser NÃO-mintável sem o
linearizador por TODO caminho (ctor, deserialize, default, clone, struct-literal).

### A.2 Resolução PERSISTIDA
A resolução de um canal (Pending → terminal, e a geração de cancelamento) é
DURÁVEL, não só in-memory: um restart do engine NÃO pode (a) reabrir um canal já
resolvido/fechado, nem (b) perder um revoke/tombstone já aplicado, nem (c)
reaproveitar uma claim one-shot já consumida. A persistência usa o mesmo
`(authz_epoch, roster_digest)` + geração de cancelamento como chave de
autoridade; leitura na recuperação é fail-closed (ausência/ambiguidade = fechado,
não aberto). Isto é ADIÇÃO ao contrato-fonte (que descrevia o linearizador
in-process); a durabilidade é o que a decisão DP-A do Caio exige a mais.

### A.3 Grafo de estados CONCRETO (tipos, não só transições)
Os estados do contrato-fonte §5 viram TIPOS concretos distintos (estados
inválidos não-representáveis), preservando as invariantes:
`PendingFinished → Promoted(VerifiedMeshPeer,DialPermit) → Dialing → Pumping →
Closed`, mais `Revoking → Closed`. `Promoted`/`Dialing` sem caminho de volta,
sem retry/segundo-dial/migração; `Closed` idempotente (close repetido não recria
estado nem minta permit). A transição de promoção é a CAS única do §5.1.

### A.4 Carriers de #367 preservados e ligados
`VerifiedMeshPeer`/`DialPermit`/`OwnerSitePromotedChannel` de #367 permanecem os
carriers selados; UMA construção por carrier, SÓ pelo linearizador, deny-only
até o linearizador existir, NENHUM `Ok(...)` de conveniência. Se a promoção
passar a embutir material do tuplo nesses carriers (hoje são seals vazios), o
`Debug` derivado vira CUSTOM redigido E o contrato de teste é ATUALIZADO (nunca
enfraquecido: o pin "cannot be created outside module" fica mais forte).

### A.6 CASA do Pending de produção + preservação DURA do guard #367 (BLOQUEANTE)
Grounding do @jovian (dp1-a-guard-surface-grounding.md): o teste
`owner_site_promotion_skeleton_is_deny_only_and_unwired` impõe em
`owner_site_promotion.rs` contagens DURAS. MÉTRICA (corrigido v1.1 — a string
COM PARÊNTESE `VerifiedMeshPeer(`/`DialPermit(` casa a DECLARAÇÃO tuple-struct
`struct VerifiedMeshPeer(VerifiedMeshPeerSeal)` E qualquer CONSTRUÇÃO, mas NÃO
referências de tipo como `Promoted(VerifiedMeshPeer, DialPermit)`): o teste
afere `VerifiedMeshPeer(`==**1** e `DialPermit(`==**1** (as DUAS DECLARAÇÕES,
ou seja ZERO construções além delas — byte-intacto), `pub(crate) fn`==1 (só o
`promote()` deny-only), `!Ok(`, `!Serialize/!Deserialize/!serde`, módulo UNWIRED. A decisão do Caio ("guards
#367 intactos") os preserva. RESOLUÇÃO NORMATIVA (arquitetural — separar a
FRONTEIRA da AUTORIDADE):

**Regra A.6.1 — casa separada, MÓDULO CONFIRMADO.** `owner_site_promotion.rs`
continua sendo SOMENTE a fronteira de carriers deny-only: as definições seladas
(VerifiedMeshPeer/DialPermit/OwnerSitePromotedChannel/OwnerSitePromotionRequest)
+ o único `promote()` deny-only. O `PendingFinished` de PRODUÇÃO, o grafo de
estados concreto, o linearizador e a ponte A2 (Parte B) moram no módulo de
autoridade **`owner_site_authority.rs`** — que **JÁ EXISTE** (origin/main
50b7e3d8, 1363 linhas; verificado independente por @safia e @jovian). DP-A o
**ESTENDE, NÃO cria** (evita a classe de erro "assumir módulo novo/inexistente"
que bateu 4× hoje). Esse módulo já É o padrão da Fatia-1 instanciado: header
"pre-effect owner-site membership and roster authority types... production has no
constructor that can produce an authority"; `OwnerSiteAuthorityGeneration`/
`OwnerSiteRemotePrincipal`/`OwnerSiteRosterScope`/`OwnerSiteBindingId` são
`pub(crate) struct` com ctor SOMENTE `#[cfg(test)] injected_for_harness` +
acessores de produção, sem ctor de produção; `#![allow(dead_code)]` "unreachable
until the reviewed A2/provider slices"; tem SEU PRÓPRIO contract-test em
claw_store_contract.rs. NUNCA em `owner_site_promotion.rs`. Consequência: em
DP-A/DP1, `owner_site_promotion.rs` fica BYTE-GUARD-INTACTO — zero 2ª pub fn,
zero `Ok(`, zero serde adicionados ali; `owner_site_authority.rs` é que carrega
Pending/grafo (preservando+fortalecendo o guard PRÓPRIO dele, A.6.4).

**Regra A.6.2 — ZERO CONSTRUÇÕES de carrier até o linearizador (DP2); métrica factual.**
Em DP-A/DP1 (zero-efeito) NINGUÉM CONSTRÓI VerifiedMeshPeer/DialPermit. PROVA
(formulação @adriana, mais robusta que um count cru), por MÓDULO:
- `owner_site_promotion.rs` fica BYTE-INTACTO (diff vazio / SHA preservado ali) —
  o que JÁ implica que a string-match `VerifiedMeshPeer(`/`DialPermit(` permanece
  no baseline mergeado (==1 cada = as declarações tuple-struct; ==0 construções
  além delas). Não precisa de grep de count separado; byte-intacto subsume.
- `owner_site_authority.rs` (o módulo EDITADO) prova por COUNT LITERAL: a
  string-match `VerifiedMeshPeer(`/`DialPermit(` == 0 lá (nenhuma construção;
  referências de tipo tipo `Promoted(VerifiedMeshPeer, DialPermit)` NÃO casam a
  string com parêntese). É ESTE o grep que importa — é o módulo em edição.
A construção de carrier em DP2 é AUTORIZADA EXCLUSIVAMENTE pelo linearizador (em
`owner_site_authority.rs`) via uma testemunha/capability NÃO-FORJÁVEL que só o
módulo do linearizador produz — MAS a EXPRESSÃO física de construção
`VerifiedMeshPeer(seal)` vive em `owner_site_promotion.rs`, porque o seal
(`VerifiedMeshPeerSeal`, verificado SEM `pub` na fonte) é PRIVADO a esse módulo e
só ali é construível ("The deliberately private seal prevents other crate
modules from minting it"). AUTORIZAÇÃO ≠ EXPRESSÃO: são coisas distintas (correção
@jovian/@adriana; a redação anterior "construção só existe no linearizador" era
impossível em Rust e contradizia A.6.3). MECANISMO CONCRETO (fonte: o doc-comment
do próprio `promote()` — "A future reviewed implementation may replace this
rejection with the one atomic Pending → Promoted transition"): DP2 SUBSTITUI O
CORPO do `promote()` já existente — ele chama o linearizador de authority pelo
witness, constrói o carrier ali dentro (onde o seal é construível) usando o
witness, e retorna `Ok`. Isso mantém `pub(crate) fn`==1 ESTÁVEL (substitui o
corpo, NÃO adiciona 2ª fn) enquanto `VerifiedMeshPeer(`/`DialPermit(` vai de
1→2 (declaração + a construção no corpo substituído) — exatamente A.6.3. O
witness é o ÚNICO elo entre os módulos; o seal NUNCA sai de privado. Nunca um
construtor `pub` simples; o `Ok(` de sucesso passa a existir SOMENTE no corpo
witness-gated do `promote()` em DP2 (o guard `!Ok(` é reformulado junto, A.6.3),
nunca `Ok(` de conveniência fora dele.

**Regra A.6.3 — o guard #367 é REFORMULADO mais forte quando DP2 liga, nunca
mais fraco.** Quando DP2 introduzir a construção via linearizador,
`owner_site_promotion.rs` deixa de ser BYTE-INTACTO/unwired (a string-match passa
de ==1 = só a declaração para ==2 = declaração + a construção) — e nesse MESMO PR o
teste de contrato é REESCRITO para uma invariante ESTRITAMENTE MAIS FORTE, não
removida: "carrier AUTORIZADO exclusivamente pelo linearizador (em
`owner_site_authority.rs`) via witness não-forjável, com a EXPRESSÃO de
construção no CORPO SUBSTITUÍDO do único `promote()` em `owner_site_promotion.rs`
(seal privado) — `pub(crate) fn` permanece ==1 (corpo trocado, NÃO fn nova),
`VerifiedMeshPeer(`/`DialPermit(` vão de 1→2, `Ok(` SÓ na via witness-gated
(nunca de conveniência), e promotion passa a ser WIRED apenas ao linearizador de
authority". Enfraquecer o guard (trocar por
um mais permissivo, ou remover a contagem sem uma mais restritiva no lugar) é
NO-GO. Meu gate verifica: guard-novo ⊇ guard-#367 em rigor (set-coverage).

**Regra A.6.4 — `owner_site_authority.rs` PRESERVA+FORTALECE o guard próprio dele.**
O módulo já tem contract-test próprio (o padrão "production has no constructor",
ctors só `#[cfg(test)] injected_for_harness`). O `PendingFinished` de produção e
o grafo, ao ESTENDER esse módulo, herdam minhas regras de posse (A.1:
construtor+campos privados, sem Serialize/Clone/Deserialize/Default, Debug
redigido) E preservam o guard existente do módulo — o teste próprio dele é
ATUALIZADO só pra ficar MAIS FORTE (o novo Pending também sem ctor de produção,
só via linearizador na Fatia-2), nunca enfraquecido. Em DP1/Fatia-1 provam
zero-efeito por grep negativo (sem connect/dial/socket/bytes) e "peer/permit não
construídos aqui" — a string-match `VerifiedMeshPeer(`/`DialPermit(` == 0 em
`owner_site_authority.rs` até a Fatia-2 ("aqui" = o módulo EDITADO, base 0;
distinto de `owner_site_promotion.rs`, que fica ==1 pelas declarações e é provado
por BYTE-INTACTO, não por este grep). O módulo PODE usar `Ok(`
na sua lógica de transição PURA (não está sob o guard `!Ok(` do #367, específico
da FRONTEIRA deny-only) — mas nenhuma transição inerte produz carrier/efeito sem
o linearizador da Fatia-2.

### A.5 Linearizador, rechecks §5.1, fence de revoke (invariantes; impl em DP2)
O contrato REAFIRMA como vinculantes: registro único por
`(ws_instance,channel_id,channel_epoch,CB)`; registro e aplicador de
roster/tombstone no MESMO lock/CAS/ator; NENHUM booleano de auth lido e usado
depois de `await` (anti-TOCTOU); os 7 rechecks do §5.1 no ponto único de
promoção sem soltar o linearizador; a ordem de revoke do §8.2 (persistir+avançar
geração → marcar Revoking → publicar fence e soltar sem await → drenar → reentrar
e confirmar); `(authz_epoch,roster_digest)` exato — epoch igual com digest
diferente é REJEIÇÃO. A IMPL destes é DP2 (o gate anti-TOCTOU é meu em DP2); o
contrato os FIXA como norma.

### A.7 FATIAMENTO SEGURO (BLOQUEANTE — ponto que a @kiana exige fechar)
Nenhum ctor de carrier e nenhum WIRING da ponte A2 pode furar o guard #367 nem
abrir a rota antes da fatia AUTORIZADA. A norma fixa três fronteiras de fatia,
cada uma seu PR SHA-bound com meu GO; GO de uma NUNCA autoriza a seguinte:

**Fatia-1 (TIPOS INERTES, zero efeito, guard #367 INTACTO):** o `PendingFinished`
de produção (tipo + tuplo §3 completo + posse A.1) EM `owner_site_authority.rs`
(EXISTENTE — ESTENDER, não criar, A.6.1); o grafo de
estados como TIPOS + transições PURAS; o TIPO `AuthenticatedConfidentialChannel`
DEFINIDO mas NÃO-WIRED (nenhum mint/distribuição o consome ainda); corpus/guards.
**EXPRESSO (refinamento @adriana, vinculante): a PROMOÇÃO happy-path NÃO ocorre
na Fatia-1.** `Pending → Promoted` é ESTRUTURALMENTE INALCANÇÁVEL aqui — `Promoted`
detém os carriers, cuja CONSTRUÇÃO é PROIBIDA até a Fatia-2 (zero construção — a
string-match `VerifiedMeshPeer(` não é criada em authority, e promotion fica
byte-intacto). O teste
PROVA a promoção INALCANÇÁVEL (nenhum caminho constrói `Promoted`) e exercita
SOMENTE as transições puras NÃO-promoção (ex.: `Pending → Closing → Closed`) +
os helpers puros (validar-transição, comparar-geração como funções puras sobre
entradas sintéticas). PROIBIDO nesta fatia: construir VerifiedMeshPeer/DialPermit
(ZERO CONSTRUÇÕES além das declarações — promotion BYTE-INTACTO = string-match
`VerifiedMeshPeer(`/`DialPermit(` ==1 PRESERVADO, as declarações; authority
string-match ==0), QUALQUER happy-path de promoção,
persistir, wirar a ponte A2 a mint, abrir rota. Prova: grep negativo (sem
connect/dial/socket/bytes; sem mint consumindo a prova) + teste de promoção-
INALCANÇÁVEL + **TRÊS guards de contrato VERDE-OU-MAIS-FORTE, cada um nomeado
(refinamento @adriana/@kiana/@jovian, vinculante):**
(i) `owner_site_promotion_skeleton_is_deny_only_and_unwired` (#367,
claw_store_contract.rs) — BYTE-INTACTO na Fatia-1 (a fronteira deny-only não
muda);
(ii) `owner_site_pre_effect_route_is_router_only_and_capability_sibling`
(claw_store_contract.rs:558, o guard PRÓPRIO de owner_site_authority.rs) — VERDE
e SÓ FORTALECIDO, com rigor SUPERSET EXPLÍCITO (guard-novo ⊇ guard-atual por
set-coverage, MESMA disciplina da A.6.3): TODA assertiva atual preservada
(route-only `auth==owner_site_pre_effect`/`operation.is_none()`; unwired de
bootstrap; `mod owner_site_capability/authority/challenge` crate-private no lib;
ctor admitindo SÓ `#[cfg(test)] injected_for_harness`; capability sem `use
owner_site_challenge`) + as novas do `PendingFinished` de produção ADICIONADAS,
NUNCA removida nem enfraquecida;
(iii) as assertivas de módulo crate-private/`#[cfg(test)]`-ctor do próprio
`PendingFinished` novo (posse A.1) — presentes e provadas.
Meu gate verifica os TRÊS por set-coverage: guard-Fatia-1 ⊇ guard-atual em rigor,
nunca ⊂.

**Fatia-2 (LINEARIZADOR, construção via witness, persistência; sem rota/dial):**
o linearizador + construção de peer/permit SOMENTE via witness não-forjável +
resolução PERSISTIDA (A.2) + rechecks §5.1 + fence de revoke (§8.2). AQUI, e só
aqui, o guard #367 é REFORMULADO MAIS FORTE (A.6.3), e AQUI a promoção
happy-path passa a ser alcançável (sob o linearizador). **EXPRESSO (refinamento
@adriana, vinculante): PERSISTÊNCIA, STORE, CHAVE e RECUPERAÇÃO pertencem SOMENTE
à Fatia-2** — nenhum traço deles na Fatia-1. Ainda SEM abrir a rota de
sinalização, SEM dial, SEM bytes. Prova: matriz de barreiras de revoke (§8) +
set-coverage do guard-novo ⊇ guard-#367 + recuperação fail-closed testada.

**Fatia-3 (ABERTURA DA ROTA — WIRING da ponte A2, separadamente autorizada):** só
AQUI o `AuthenticatedConfidentialChannel` é WIRED para gatear o mint/distribuição
do rendezvous-id (a rota R1 ABRE), com o fail-closed da Parte B, mint idempotente
e caveat próprio. **EXPRESSO (refinamento @adriana, vinculante): o ELEMENTO ÚNICO
EXATO do mint (o claim/binding de idempotência da Parte B.3) e o CAVEAT próprio
pertencem SOMENTE à Fatia-3** — não aparecem na Fatia-1 nem na Fatia-2. Dial/pump/
bytes de site seguem a escada DP3–DP5 do contrato-fonte §10, cada um sua fatia.
PROIBIDO antes desta fatia: qualquer caminho em que a prova B.1 gateie um mint
real, ou em que o elemento de idempotência/caveat exista.

Invariante transversal (meu gate, cada fatia): o TIPO pode existir inerte cedo; a
CONSTRUÇÃO (ctor de carrier), a PERSISTÊNCIA e o WIRING (rota) são efeitos que só
entram na fatia própria autorizada. Antes disso: ZERO CONSTRUÇÕES além das
declarações (promotion BYTE-INTACTO = string-match ==1 preservado / authority
string-match ==0), unwired, rota fechada.
Uma fatia que adiante ctor/persistência/wiring = NO-GO.

## PARTE B — Sessão A2 como PROVA TIPADA de canal autenticado+confidencial (R1-A)

### B.1 O tipo de prova
Define-se um fato TIPADO, selado, não-forjável — `AuthenticatedConfidentialChannel`
(nome final a alinhar) — CONSTRUÍVEL SOMENTE a partir de uma sessão A2
owner-present VIVA e validada (o mesmo `TransportState` pós-C3 / a mesma
autoridade da Parte A). Ele é a materialização, no código, da propriedade que o
R0b R2 exige: o canal é autenticado E confidencial na CAMADA DE APP (o handshake
Noise_XXa2v1 dá as duas). NÃO deriva de header (x-forwarded-proto proibido), de
TLS-por-inferência, nem de endereço. É o "fato tipado" do meu D1 — resolve a
ausência de fato TLS no listener household (achado da alaine no recon R1).

### B.2 Distribuição do rendezvous-id exige a prova (fail-closed)
O mint e a distribuição do rendezvous-id (peça 5, R0b §1) SÓ podem emitir/entregar
o id SE portarem um `AuthenticatedConfidentialChannel` vivo. Ausência/staleness/
mismatch da prova ⇒ FECHA antes de qualquer CSPRNG, insert de tabela, counter de
mint ou byte de resposta (o enforcement mínimo do §3.2 do recon da alaine, que
adoto). SEM fallback plaintext, SEM downgrade. Isto satisfaz o fail-closed do R2
do R0b sobre um fato tipado — exatamente o meu D1 preferido (canal A2), agora
concreto porque a Parte A cria a rota A2 de produção da qual ele depende.
(Alternativa TLS: só onde A2 não alcança; aí exige uma superfície
`AuthenticatedTls` tipada equivalente — fora do escopo desta decisão, contrato
futuro.)

### B.3 Mint idempotente + caveat próprio (meu D6)
O handler de mint do rendezvous-id é IDEMPOTENTE/claim-based: um PoP replayado
dentro da janela de 60 s (o PoP não tem nonce cache) NÃO minta um 2º id — claim
único ou binding a elemento único da request. A autorização usa CAVEAT DE
OPERAÇÃO PRÓPRIA (uma operação nova, escopada ao mint de rendezvous), NUNCA
`ClawsList` por analogia (reusar over-concede autoridade). A operação nomeada é
detalhe da diretiva do @jovian; a idempotência e o escopo próprio são norma
minha.

### B.4 Fronteira honesta
A prova B.1 atesta o CANAL (autenticado+confidencial), não a identidade do ALVO
owner-mesh — essa é o binding de R4 derivado de `MachineCert.m_pub`
(`verify_against_household_root`), como fixei no R0a. Os dois são distintos: B.1
= canal; R4 = alvo. O servidor de sinalização untrusted permanece incapaz de
forjar id (o engine minta sob a prova B.1; o servidor só CASA ids apresentados).

## 2. Invariantes que ESTE contrato carrega (rastreabilidade)
R0b R2 (fail-closed sobre fato tipado) · D1 (A2 preferido; fato tipado não
header) · D3 (limits não-desabilitáveis, contrato-fonte §7) · D4 (posse/seal) ·
D5 (replay-set fail-closed) · D6 (mint idempotente + caveat próprio) ·
contrato-fonte §2/§2.1/§3/§5/§5.1/§8/§11 integrais · byte-pin do corpus DP
`46a0a3ad` continua sendo da PRIMEIRA fatia DP que serialize (§9), não desta
norma.

## 3. NO-GO herdado (§11) + adições
Tudo do §11 do contrato-fonte, MAIS: emitir/distribuir rendezvous-id sem
`AuthenticatedConfidentialChannel` vivo; mint não-idempotente; reusar `ClawsList`
para o mint; `PendingFinished` de produção construível fora do linearizador ou
com Serialize/Clone/Deserialize/Default; resolução NÃO persistida que reabra
canal resolvido ou perca revoke num restart.

## 4. Pontos que a diretiva de impl do @jovian fecha (não invento aqui)
1. Nome final e módulo-dono do `AuthenticatedConfidentialChannel` e do
   `PendingFinished` de produção.
2. Mecanismo exato de PERSISTÊNCIA da resolução (store, chave, recuperação
   fail-closed) — respeitando A.2.
3. Nome da operação de caveat do mint (respeitando B.3: própria, não ClawsList).
4. Como os carriers de #367 passam a embutir (ou referenciar) o tuplo sem
   enfraquecer o contrato de teste (A.4).
5. Fatiamento DP-A vs a escada DP2–DP5 do contrato-fonte §10 (esta norma é
   transversal; a impl segue fatiada e SHA-bound, cada uma com meu GO).

## 5. Verificação
HISTÓRICO: a v1-final (raw SHA-256 629ce978) teve GO dos três MAS continha dois
erros (métrica de count promotion ==1≠0; conflação autorização-vs-expressão em
A.6.2/A.6.3) pegos pela @alaine no impl + na re-revisão; por isso os GOs da
v1-final NÃO valem para esta v1.1. Esta v1.1-final teve RE-REVISÃO DUPLA FECHADA
sobre os bytes 8e9f27d5: @jovian re-GO de arquitetura (leu A.6.2/A.6.3 inteiras +
varredura de conflação/contagem-zero, recomputou o hash) + @adriana re-GO
funcional + Fatia-1-intacta (comparação word-by-word do bloco A.7), ambos direto
no arquivo. Eu sou a autora → NÃO auto-ratificado (dois revisores independentes +
a coordenadora). Esta é a NORMA VINCULANTE. A partir daqui, cada fatia de impl da
@alaine recebe meu GO SHA-bound verificado contra ESTA norma + @adriana funcional
+ pin Phase-0 do @jovian se tocar admin/rust. verificador ≠ autor no nível de
código. Congelada por raw SHA-256 (a tripla path+versão+SHA-256+tamanho está na
mensagem de emissão da v1.1-final). Alterar a norma exige nova versão + novo hash
+ nova revisão, nunca reformatar em lugar.
