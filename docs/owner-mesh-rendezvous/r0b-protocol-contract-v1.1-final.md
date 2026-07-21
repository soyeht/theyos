# R0b — Contrato de protocolo da sinalização de rendezvous (v1.1-final)

STATUS: REVISÃO FECHADA. @safia GO (R1+R2) FEITO · @adriana re-ok final dos
err.* FEITO · caso de borda `pairing_full` resolvido. Texto RECONCILIADO;
pronto para freeze por raw SHA-256 deste texto (a safia vincula o GO formal ao
SHA emitido sobre esta versão). O freeze do CORPUS sintético (tripla
commit+path+sha256 no repo) é passo DOWNSTREAM, na fatia de impl da sinalização
(parqueada com o Caio junto da peça 5); este SHA congela o DESIGN revisado.

Autor: @jovian · 2026-07-17 · v1.1-final integra a revisão de segurança da @safia
(`r0b-safia-security-review-v0.md`: R1/R2 bloqueadores, R3/R4 endurecimento,
D-A/D-B/D-C do §9) + a revisão funcional da @adriana (matriz §7, gaps de
versão e cap-por-frame, achado do oráculo por timing, ordem de parse). Base:
diretiva da peça 5 (D1–D5), contrato @safia (I1–I10) + addendum (S1–S3), R0a
(binding = R4). Escopo: SÓ a superfície de sinalização untrusted-by-design.
STATUS: pós-revisão-tripla; freeze por raw SHA-256 após releitura final da
@safia (R1+R2) + re-ok da @adriana dos err.* novos.

## Changelog v0→v1
- R1 (safia, BLOQUEADOR): matriz §7 ganhou o eixo CODEC completo (~9 linhas de
  frame/CBOR), cada uma com err.* distinto + regra de decode canônico.
- R2 (safia, BLOQUEADOR): canal OOB do rendezvous-id virou PRÉ-CONDIÇÃO
  load-bearing; §1 reescrito com a recon (auth CONFIRMADO, confidencialidade
  MANDADA, distribuição do id efêmero ESPECIFICADA — ver §1).
- R3/R4 (safia): caps vinculam dados server-supplied; resíduo SSRF-LAN do M1
  documentado (§3/§4).
- D-A (timing §9.4) = (i)+(iii): NENHUM `RzClose` em falha; wire uniforme.
- D-B (versão) e D-C (cap-por-frame) confirmados. TTL fixado em 20 s.
- Ordem de parse fixada (versão antes do dispatch de tipo — pergunta @adriana).
- v1.1 (releitura final @safia + 2ª revisão @adriana): R1 GO, R2 GO após a
  linha FAIL-CLOSED de transporte (§1, código recusa operar sem canal
  autenticado-TLS). Achados @adriana resolvidos: (i) `close_unauthorized`
  ganhou BINDING DE TRANSPORTE (id amarrado às 2 sessões que primeiro fizeram
  RzHello; teardown só de sessão bound) — torna-o alcançável/testável e fecha
  teardown por eavesdropper; (ii) CADEIA DE PRECEDÊNCIA completa no §2 (8 passos
  ordenados) — multi-violação determinística; (iii) `oversized_frame` movido
  para 1º check em BYTES CRUS antes de decodar; (iv) gap fechado: novo
  `err.malformed_cbor` (não-CBOR desde o início) distinto de `truncated_frame`
  e `noncanonical_cbor`.

## 0. Papel e não-objetivos
Troca de DICAS DE ENDEREÇO entre Device-D e Claw-M + reflexive observado pela
própria sessão. NÃO transporta identidade, chave, autorização, nem datapath.
Autenticação das pontas = A2 fim-a-fim (fora daqui). Servidor incapaz de
ler/forjar POR CONSTRUÇÃO (I1). NÃO existe mensagem de modo (I5).

## 1. rendezvous-id + canal de distribuição (I1 + R0a + R2 — load-bearing)
- Opaco, CSPRNG, ≥128 bits, single-use, TTL 20 s (fixado @safia), não-linkável.
- NÃO deriva de segredo NEM de identidade: explicitamente NÃO é/deriva do
  `ClawVpnMobileClawId`, target-identity, household_id, nem baseMeshPublicKeyHex
  (R0a). Identidade é A2 + binding R4.
- **Canal OOB (R2 — a segurança do emparelhamento inteira repousa aqui):** o id
  é mintado SERVER-SIDE (engine owner-mesh) e entregue às duas pontas SOMENTE
  por canal autenticado E confidencial. Recon (@jovian, main 50b7e3d8):
  - AUTENTICAÇÃO — CONFIRMADA: o canal de config de máquina é
    `/api/v1/household/machines` (`handlers_household.rs:150`), com gate
    owner-auth `household_auth::authorize_request(… Operation::ClawsList …)`.
  - CONFIDENCIALIDADE — MANDADA, não observada: é propriedade de TRANSPORTE
    (TLS) que o código estático não prova. Requisito normativo: o transporte da
    sinalização E do canal de distribuição do id DEVE ser TLS server-autenticado
    (fecha eavesdropper on-path; sem isso o emparelhamento é não-autenticado).
  - **FAIL-CLOSED (R2, linha final @safia):** a fatia R1 (canal concreto) DEVE
    RECUSAR emitir o rendezvous-id OU candidatos por qualquer transporte que não
    seja o canal autenticado-TLS mandado — SEM fallback plaintext, SEM
    downgrade. Isso converte o mandato de deployment num INVARIANTE enforçável
    por código (o código recusa operar sem o canal), verificado concreto no
    head da fatia R1. O bar de propriedade de transporte é fail-closed no
    código, não prova-por-fonte.
  - **Servidor untrusted só CASA, não MINTA (reforço @safia):** o engine minta
    o id e o distribui confidencial; o servidor de sinalização untrusted apenas
    casa ids APRESENTADOS. Logo servidor hostil não FORJA id válido — só faz DoS
    de ids que já viu (inerente, aceito).
  - DISTRIBUIÇÃO DO ID EFÊMERO — ESPECIFICADA, não pré-existente: os tipos
    `ClawVpnMobileRendezvousToken`/`RendezvousToken` existem no modelo puro
    (`claw_vpn_mobile_state.rs:470`) mas SEM wiring de produção (R0a). Logo o
    "reusa o canal do endpoint_npub" da v0 era impreciso — `endpoint_npub` nem
    existe no engine. A fatia R1 pina o canal concreto: reuso da sessão A2
    owner-present (já autenticada fim-a-fim) OU endpoint owner-authed sobre TLS.
- Modelo de exposição do id: o id transita a sinalização em claro (campo de
  `RzHello`). Servidor hostil OU eavesdropper on-path que aprenda o id pode
  pré-consumir (DoS de emparelhamento) e ver candidatos. Para o SERVIDOR isso é
  inerente (untrusted; já pode negar serviço) — aceito. Para eavesdropper, o
  TLS mandado acima é a defesa.
- Emparelhamento + BINDING DE TRANSPORTE (resolve o achado @adriana sobre
  `close_unauthorized`): as duas pontas apresentam o mesmo id; o servidor amarra
  o id às (até 2) SESSÕES DE TRANSPORTE que primeiro apresentaram RzHello nele,
  casa os dois lados e reflete candidatos. Como o protocolo é sem-identidade e o
  id transita em claro, "conhecer o id" NÃO autoriza operações — a autorização é
  a SESSÃO DE TRANSPORTE bound (binding de transporte, não de identidade; I2
  preservado). Consumo na primeira troca bem-sucedida. Uma 3ª conexão com o id
  correto mas fora das 2 sessões bound é rejeitada — é isto que torna
  `err.close_unauthorized` ALCANÇÁVEL e testável, e fecha o teardown por
  eavesdropper (quem só viu o valor no fio está noutra sessão → não pode fechar;
  o TLS mandado fecha até o eavesdropper passivo).
- **Slots de emparelhamento cheios (caso de borda @adriana, análogo de
  estabelecimento do `close_unauthorized`):** uma 3ª tentativa de `RzHello` no
  MESMO id, depois que 2 sessões já se ligaram nele, NÃO tem slot por
  construção → rejeitada como `err.pairing_full` (classificação LOCAL/interna
  do servidor; no FIO segue a regra D-A — nada é emitido, a sessão intrusa vê
  silêncio→TTL). É ergonomia de estabelecimento, não muda B6 nem oráculo:
  distinto de `close_unauthorized` (teardown vs join) e de
  `unknown_rendezvous_id` (id existe e está cheio vs id nunca-emitido).

## 2. Shapes de mensagem (canonical-CBOR, versionado)
Domínio/versão/tipo em todo envelope; cardinalidade e tipos exatos; nada
opcional silencioso.

**CADEIA DE PRECEDÊNCIA de parse (fixada — @adriana: um fixture com N violações
simultâneas tem de ter resultado DETERMINÍSTICO).** Ordem estrita; o PRIMEIRO
check que falha vence e define o err.*:
1. tamanho em BYTES CRUS — `err.oversized_frame` (ANTES de qualquer decode; um
   frame gigante é rejeitado sem custo de parse — mesma lógica do cap de
   contagem D-C).
2. decodabilidade CBOR: bytes que não formam CBOR válido desde o início
   (major-type inválido) → `err.malformed_cbor`; bytes que acabam no meio →
   `err.truncated_frame`. (São modos DISTINTOS — gap achado pela @adriana.)
3. forma canônica (re-encode byte-a-byte ≠ bytes, padrão DP) →
   `err.noncanonical_cbor`.
4. domínio → `err.wrong_domain`.
5. versão (EXATA; sem down-negotiation, D-B) → `err.version_unsupported`.
6. dispatch de TIPO → `err.unknown_frame`.
7. forma/cardinalidade do payload do tipo → `err.wrong_shape`.
8. campo desconhecido/extra → `err.unknown_field`.
Depois disso: cap de contagem de candidatos (`err.frame_too_large`, §4) e os
checks de POLÍTICA (§7 eixo política). Consequência determinística: versão
errada + tipo desconhecido → `err.version_unsupported` (passo 5 < 6); malformado
+ oversized → `err.oversized_frame` (passo 1 < 2); etc.
- `RzHello` (D-ou-M → servidor): `{ v, rendezvous_id, candidates[] }`, cada
  candidate ∈ classes permitidas (§3). SEM identidade, SEM segredo.
- `RzPeer` (servidor → D-ou-M): `{ v, rendezvous_id, peer_candidates[],
  observed_reflexive }`. `observed_reflexive` = endereço-fonte visto pelo
  servidor (única info que o servidor adiciona; I4-b) — HINT NÃO-CONFIÁVEL (R3).
- `RzOk` (servidor → D-ou-M): confirma emparelhamento no SUCESSO. **É o ÚNICO
  frame de saída em caminho terminal** (ver §7/D-A: NÃO há frame de falha).
- AUSENTE POR DESIGN: `RzUseRelay` / campo de modo / prioridade / ordem com
  efeito de downgrade (I5 — critério de rejeição).
- `RzClose` (participante bound → servidor): teardown explícito, honrado SÓ
  numa das 2 sessões de transporte bound (acima); de fora → `err.close_unauthorized`.
- AUSENTE POR DECISÃO D-A: `RzClose` no caminho de FALHA. Falha ⇒ o servidor
  não emite nada; o id expira por TTL (wire uniforme, §7). O `RzClose` acima é
  só teardown de sucesso; a distinção grossa sucesso-vs-falha é resíduo
  v1-out-of-scope, ver §7.

## 3. Classes de candidato (I4) + caps + resíduo M1
Exatamente três; qualquer outra rejeitada na borda: (a) LAN/RFC1918;
(b) reflexive da PRÓPRIA sessão; (c) relay de offer ASSINADA via roster (I6).
NUNCA endpoint público arbitrário.
- Exposição do M1 (leva C1 em claro) só a candidatos dessas classes;
  `MAX_M1_PER_SESSION` = 8 (≤ MAX_CANDIDATES).
- **Resíduo SSRF-LAN (R4 @safia — documentado):** um servidor hostil pode dar
  um candidato classe-(a) apontando a um host LAN interno arbitrário → o cliente
  envia C1 (household_id, route, intent em claro) a esse host, até MAX_M1. C1
  não carrega segredo cripto (identidade é A2), mas expõe metadados a um host
  LAN escolhido pelo atacante. O cap MAX_M1 é o que bound isto; registrado como
  exposição conhecida de v1.

## 4. Orçamentos anti-amplificação (I3) — numéricos, testáveis (fixados @safia)
- `MAX_CANDIDATES_PER_FRAME` = 8 (D-C): teto de candidatos DENTRO de um frame,
  no PARSE, antes de qualquer estado de sessão. Excedeu → `err.frame_too_large`.
  DISTINTO de `err.oversized_frame` (bytes, R1): dois guards de parse (contagem
  vs bytes), dois err.* (B6).
- `MAX_ATTEMPTS_PER_CANDIDATE` = 3 · `MAX_CANDIDATES_PER_SESSION` = 8 ·
  `MAX_BYTES_TO_UNVERIFIED_ENDPOINT` ≤ 3×M1 · `BACKOFF` 250ms→2s teto 2s.
- **R3 (safia — caps vinculam dados SERVER-SUPPLIED):** o cliente aplica
  `MAX_CANDIDATES_PER_SESSION` sobre os `peer_candidates[]` RECEBIDOS — servidor
  hostil manda 1000, o cliente tenta no máximo o cap, nunca 1000.
- Razão bytes-enviados/bytes-de-hint limitada (não-amplificador; M1 já capado).

## 5. Fallback mecânico (I5)
Decisão LOCAL do cliente: orçamento direto esgotado OU `T` = 5 s sem path → tenta
o relay da lista assinada (§3-c). Verificável por relógio simulado. Servidor
NUNCA comanda modo.

## 6. Revoke fence (I7)
Mudança de `(authz_epoch, roster_digest)` ou revoke invalida sessão, candidatos,
emparelhamento e relay; `requires_new_a2` ⇒ re-rendezvous completo; zero cache
de conectividade atravessa a barreira.

## 7. Matriz NEGATIVA (S2; FROZEN raw SHA-256 antes de serializar). err.* DISTINTO por MODO (B6).

### Eixo CODEC / PARSER (R1 @safia — o servidor hostil ataca o parser primeiro)
| Ataque | Resultado | err.* |
|---|---|---|
| frame acima do máx. de BYTES (raw, 1º da cadeia §2) | recusado sem decodar | `err.oversized_frame` |
| bytes não-CBOR desde o início (major-type inválido) | recusado no decode | `err.malformed_cbor` |
| truncado / EOF no meio | recusado no decode | `err.truncated_frame` |
| CBOR válido mas não-canônico (re-encode ≠ bytes) | recusado antes de interpretar | `err.noncanonical_cbor` |
| versão de envelope errada | recusado, sem downgrade (D-B) | `err.version_unsupported` |
| domínio errado | recusado | `err.wrong_domain` |
| cardinalidade/tipo de campo errado | recusado | `err.wrong_shape` |
| tipo de frame desconhecido (ex. `RzUseRelay` forjado, mode-injection) | recusado | `err.unknown_frame` |
| campo desconhecido/extra (sem opcional silencioso) | recusado | `err.unknown_field` |
| frame acima do máx. de CANDIDATOS (contagem ≠ bytes) | recusado no parse | `err.frame_too_large` |

Ordem de avaliação = a CADEIA DE PRECEDÊNCIA do §2 (bytes→decode→canônico→
domínio→versão→tipo→shape→campo→contagem). 10 err.* de codec, distintos por
modo; nenhum colapso — `oversized`(bytes) ≠ `frame_too_large`(contagem),
`malformed`(não-CBOR) ≠ `truncated`(EOF) ≠ `noncanonical`(válido não-mínimo).

### Eixo POLÍTICA
| Ataque | Resultado | err.* |
|---|---|---|
| servidor tenta extrair identidade | zero identidade no canal | N/A — prova ESTRUTURAL (não há campo de identidade) |
| candidato fora das 3 classes (inclui endpoint público forjado — nota A) | rejeitado | `err.candidate_class_denied` |
| replay de rendezvous-id (já consumido) | barrado | `err.rendezvous_id_consumed` |
| rendezvous-id NUNCA emitido (≠ consumido) | barrado | `err.unknown_rendezvous_id` |
| `RzClose`/teardown de quem não detém o id | recusado | `err.close_unauthorized` |
| exceder orçamento de sessão (§4) | close terminal LOCAL | `err.budget_exhausted` |
| revoke durante rendezvous | sessão invalidada | `err.authority_revoked` |
| candidato hostil de classe válida | handshake A2 falha limpa | `err.a2_handshake_failed` (CROSS-LAYER, nota B) |

**Nota A (colisão intencional):** endpoint público arbitrário É, por §3, uma
instância de "fora das 3 classes" → mesmo `candidate_class_denied`. Duas
narrativas, UMA regra geral; B6 = sinal por MODO, não por linha.
**Nota B (único CROSS-LAYER):** `a2_handshake_failed` NÃO nasce no corpus do
R0b (A2 é "fora daqui", §0); NÃO congela bytes aqui — exercido pela camada A2
(corpus A2-R1/DP). Declarado para ninguém caçar bytes no corpus errado.

**Regra de observabilidade (B6 + D-A):** cada err.* é LOCAL do cliente,
distinto e testado no corpus (exceto `a2_handshake_failed`, nota B). No FIO,
por decisão D-A, TODA falha é uniforme: o servidor NÃO recebe frame de falha
algum — o cliente para e o id expira por TTL. Isso fecha o oráculo por CONTEÚDO
E por TIMING (probe-class-reject vs A2-fail eram distinguíveis por latência —
achado @adriana; resolvido tornando o wire silencioso em toda falha). Resíduo
v1-out-of-scope declarado: a distinção GROSSA sucesso (`RzOk`/`RzClose`) vs
falha (silêncio→TTL) permanece observável via tráfego — aceito em v1 (o servidor
untrusted já vê IP/timing; §1 do contrato @safia põe timing de anonimato
fora-de-escopo). Fallback mais estrito registrado (dropar `RzClose` de sucesso
também) se o leak grosso for julgado material depois.

## 8. Freeze e interop
Corpus sintético versionado non-authoritative; congelado por raw SHA-256 (tripla
commit+path+sha256, padrão DP §9) ANTES da primeira fatia que serialize. Rust e
iOS verificam os mesmos bytes crus independentemente. Estado da REVISÃO deste
DESIGN: @safia GO (R1+R2) FEITO + @adriana re-ok final FEITO — fechada. O SHA
deste texto congela o design revisado; a serialização + freeze do corpus com
tripla-de-commit real é a fatia de impl (downstream, parqueada com a peça 5).

## 9. Decisões — estado (fechadas salvo nota)
1. Numéricos (§1/§4/§5): FIXADOS @safia — TTL 20s, caps e T acima. ✓
2. Shapes §2: +domínio/versão em todo envelope, codec rejeita campo
   desconhecido, cadeia de precedência de parse fixada. ✓ (nomes finais dos
   campos = detalhe de impl, não de design)
3. Canal OOB (R2): auth CONFIRMADA; confidencialidade MANDADA via TLS;
   distribuição do id efêmero ESPECIFICADA (§1). Ponto que resta: a fatia R1
   deve escolher e provar o canal concreto (sessão A2 vs endpoint TLS) —
   verificação de deployment, não de design. ✓ no contrato.
4. Timing (D-A): (i)+(iii) — sem `RzClose` em falha; resíduo grosso v1-out. ✓
5. err.* §7: lista completa (10 codec + política). @adriana re-ok FINAL
   FEITO — todos verificados no texto (cadeia de precedência, oversized-raw-1º,
   malformed_cbor distinto, close_unauthorized com binding de transporte). ✓
6. Downgrade/versão (D-B): versão exata, sem down-negotiation. ✓
7. Caso de borda `pairing_full` (@adriana, pós-re-ok): 3º RzHello no mesmo id
   após 2 sessões bound → `err.pairing_full` (§1), resolvido em doc. ✓
