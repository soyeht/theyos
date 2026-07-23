# Contrato de segurança — Owner-site A2 data plane (v2 — RE-EMISSÃO)

Autora: safia · 2026-07-23 · por autorização direta do Caio (bloco 2026-07-23, item 3)
e despacho Prioridade-1 da kiana.

## Proveniência (leia primeiro — o que este documento É e NÃO é)

- A **v1** (`owner-site-a2-data-plane-security-contract-2026-07-16.md`) existia SOMENTE em
  /tmp volátil e foi perdida; os bytes são **irrecuperáveis**. Este v2 **NÃO alega recuperar
  byte nenhum** da v1.
- Este v2 é uma **RE-EMISSÃO**: conteúdo re-derivado pela autora original a partir de
  (a) a derivada sobrevivente (v1.1-final, raw SHA-256
  `db6ecf3705559a6ef05abade064a28af52257dcf7266b599d4d2ddfe209dfa61`, 24567B/357L,
  recuperada de file-history e re-verificada por hash), que cita e realiza o pai
  extensivamente; (b) artefatos in-repo verificados no object em `origin/main = 4cc737ef`;
  (c) as decisões registradas da autora. Onde o literal v1 sobrevive VERBATIM na derivada
  (tuplo §3; ordem de revoke §8.2), v2 o incorpora como recuperado-por-via-da-derivada.
  Onde o literal é irrecuperável (a lista dos 7 rechecks do §5.1), v2 **RE-DERIVA e
  RE-DECIDE** — marcado explicitamente como cânone NOVO.
- **Ratificação:** NÃO auto-ratificado. Vincula somente após: re-read funcional (adriana) +
  coordenação/landing (kiana) + freeze SHA-bound in-repo (tripla path+versão+raw-SHA-256+
  bytes no commit persistente). Alterar = nova versão + novo hash + nova revisão; nunca
  editar in-place.
- **Higiene de rótulos (lição C9):** invariantes escritas POR EXTENSO; rótulos soltos tipo
  "D4" são ambíguos entre famílias de decisões e NÃO são normativos aqui. ("D-A" = o item
  de timing/silêncio-uniforme do track de wire rendezvous — outro artefato, não este.)

## §1 Regra de conflito
Entre este contrato e qualquer derivada/diretiva/impl: vence a regra **MAIS RESTRITIVA**.
Uma derivada pode fortalecer, nunca enfraquecer.

## §2 Escopo e modelo de ameaça
O data plane do owner-site: promoção de canal, dial e bombeamento de bytes de site entre o
device do owner e a base, sob rede não-confiável. A autenticação e confidencialidade de
camada de app vêm da sessão **A2 owner-present** (handshake Noise_XXa2v1 — dá as duas);
nenhuma propriedade deriva de header (`x-forwarded-proto` proibido), TLS-por-inferência ou
endereço. Atacante: rede hostil + qualquer processo sem posse das chaves household; o
servidor de sinalização é untrusted-by-design (track peça-5).
### §2.1 Carriers deny-only
Até a fatia autorizada, os carriers de produção (`VerifiedMeshPeer`, `DialPermit`,
`OwnerSitePromotedChannel`, `OwnerSitePromotionRequest` — `owner_site_promotion.rs`,
guard #367) permanecem **deny-only**: seal privado, zero construção de produção, sem
Serialize/Clone/Deserialize/Default, `promote()` único que rejeita.

## §3 O tuplo imutável (15 campos) — literal preservado via derivada
```
(household, recurso_exato, rota_exata, machine_cert, device_binding,
 principal_D, ws_instance, channel_id, channel_epoch, CB, authz_epoch,
 roster_digest, fresh_until, provider_generation, cancellation_generation)
```
Capturado na promoção; **imutável**: sem setter, sem `&mut` que faça rebind. QUALQUER
divergência posterior ⇒ **fechar o canal + refazer A2**; nunca rebind. As DUAS gerações
(provider e cancellation) são campos separados.

## §5 Grafo de estados
`PendingFinished → Promoted(VerifiedMeshPeer, DialPermit) → Dialing → Pumping → Closed`,
mais `Revoking → Closed`. Sem caminho de volta a partir de `Promoted`/`Dialing`; sem
retry/segundo-dial/migração; `Closed` idempotente (close repetido não recria estado nem
minta permit). A transição de promoção é a **CAS única** do §5.1, executada pelo
linearizador (registro único por `(ws_instance, channel_id, channel_epoch, CB)`; registro
e aplicador de roster/tombstone no MESMO lock/CAS/ator).

## §5.1 Os SETE rechecks no ponto único de promoção — **RE-DERIVAÇÃO v2 (cânone novo)**
*(O literal v1 desta lista é irrecuperável. A lista abaixo é a re-decisão da autora,
vinculante a partir do freeze v2. Executam-se DENTRO do linearizador, sem soltá-lo, sem
`await` entre recheck e efeito; falha de QUALQUER um ⇒ rejeição fail-closed, nunca
promoção parcial.)*
1. **Autoridade exata:** `(authz_epoch, roster_digest)` do tuplo == o vigente, comparação
   EXATA — epoch igual com digest diferente é REJEIÇÃO.
2. **Fence de cancelamento:** `cancellation_generation` inalterada — nenhum revoke/tombstone
   aplicado desde a captura.
3. **Geração de provider:** `provider_generation` inalterada.
4. **Frescor:** `fresh_until` não expirado (expiry assinado; enforcement dupla-fonte quando
   houver deadline monotônico paralelo — ambos, nunca só o monotônico).
5. **Identidade de canal:** `(ws_instance, channel_id, channel_epoch, CB)` ainda é O ÚNICO
   registro vivo no linearizador (sem substituição/duplicata).
6. **Identidade autenticada:** `machine_cert` ainda válido contra a raiz household
   (`verify_against_household_root`) e `device_binding` ainda casa `principal_D`.
7. **One-shot:** a claim de promoção não consumida (single-use; consume-set fail-closed —
   saturação fecha, nunca evita).

## §7 Budgets e limites
Limites por-fonte (tentativas, concorrência, bytes) são **não-desabilitáveis** em produção;
falha por budget é silenciosa e uniforme (sem oráculo de qual limite bateu).

## §8 Revoke
### §8.2 Ordem vinculante — literal preservado via derivada
`persistir + avançar geração → marcar Revoking → publicar fence e soltar sem await →
drenar → reentrar e confirmar`.
Complementos vinculantes: NENHUM booleano de autorização lido antes de `await` e usado
depois (anti-TOCTOU); mudança de geração ⇒ canal fecha e exige A2 novo; zero cache de
conectividade sobrevive a revoke.

## §9 Pin de corpus
O corpus DP `admin/contracts/mobile-claw-vpn/v1/owner_site_a2_dataplane_corpus_v1.json`
(raw SHA-256 prefixo `46a0a3ad` — **verificado byte-intacto em 4cc737ef**) vincula a
PRIMEIRA fatia DP que serializar; não esta norma.

## §10 Escada de fatias
DP-A/DP1 (tipos inertes) → DP2 (linearizador/construção-via-witness/persistência) → DP3–DP5
(rota, dial, pump — cada uma fatia própria). Cada fatia: PR SHA-bound + GO da autora
verificado contra ESTA norma + funcional (adriana) + pin Phase-0 (jovian) se tocar
admin/rust. GO de uma fatia NUNCA autoriza a seguinte.

## §11 NO-GO (linha de base; derivadas podem ADICIONAR, nunca subtrair)
- Construção de carrier fora da autorização do linearizador (por QUALQUER caminho: ctor,
  deserialize, default, clone, struct-literal).
- Serialize/Clone/Deserialize/Default em tipo selado de posse; Debug derivado que vaze
  material do tuplo (Debug custom redigido).
- Booleano de auth atravessando `await`; rebind de tuplo divergente; reabrir canal
  resolvido ou perder revoke num restart (resolução tem que ser durável, fail-closed na
  recuperação: ausência/ambiguidade = fechado).
- Enfraquecer guard de contrato: reformulação só com **guard-novo ⊇ guard-atual** provado
  por set-coverage.
- Rota/dial/bytes antes da fatia autorizada; qualquer fatia que adiante
  ctor/persistência/wiring da fatia seguinte.

## Verificação
verificador ≠ autor: a autora não se auto-ratifica; cada impl é revisada contra esta norma
por quem não a escreveu. Freeze: tripla (path + versão + raw-SHA-256 + bytes) no commit
persistente in-repo; docs-only (nenhum reseal Phase-0). A derivada v1.1-final continua
válida NO QUE ELA FIXA; onde ela cita "contrato-fonte", a referência resolve para ESTE v2
a partir do freeze (regra §1 preservada: vence a mais restritiva).
