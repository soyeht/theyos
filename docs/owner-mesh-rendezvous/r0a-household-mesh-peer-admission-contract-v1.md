# R0a — Contrato canônico de admissão de peer owner-mesh (v1)

Status: **contrato canônico v1; D1–D4 ratificadas; aguardando review
SHA-bound deste novo raw**.
Base factual: `theyos` `c106fc1ffd1cf8d3af269dcbbd029f62c87cda8b`.
Autor: @jovian, com decisão de identidade de Caio e invariantes de segurança
fornecidas por @safia, 2026-07-24.

Este documento ainda não autoriza código, branch, PR, ativação ou efeito.
D2 e D3 foram ratificadas por Caio. O review deste novo raw e todos os gates
de implementação permanecem obrigatórios.

## 1. Papel e nomenclatura

R0a define a prova tipada de que uma chave pública pertence a um peer
owner-mesh atualmente admitido pela household.

Nos documentos existentes:

- R0a é o binding de identidade chamado **R4** em
  `r0b-protocol-contract-v1.1-final.md`;
- **R2** é outro objeto: o canal autenticado e confidencial de distribuição do
  `rendezvous_id`;
- R0a/R4 autentica o **alvo**; R2 autentica e protege o **canal**;
- rendezvous carrega dicas de endereço, nunca identidade ou autoridade.

Este texto é o documento canônico R0a que faltava no repositório. Ele não
reabre nem renomeia o R2 do R0b.

## 2. Escopo v1 decidido

### D1 — modelo de identidade: DUAL-CHAIN

Decisão humana de Caio:

1. **perfil máquina** para as duas máquinas já admitidas da household
   (Mac + Linux);
2. **perfil owner-device** para o telefone do mesmo dono
   (iPhone/iPadOS), por cadeia `DeviceCert → PersonCert → HouseholdRoot`.

Os dois perfis terminam na mesma root pública da household e produzem o mesmo
tipo selado de admissão. Eles não compartilham roster, certificado intermediário
nem autoridade operacional.

O telefone:

- não entra em `HouseholdRecord.members`;
- não altera `shamir_k` ou `shamir_n`;
- não recebe shard da root;
- não se torna machine issuer;
- não usa `MachineCert`;
- não recebe autoridade por analogia com máquina.

### D4 — cardinalidade de máquinas

R0a v1 cobre apenas a household M1 atual:

- duas máquinas já admitidas pelo modelo `k=n=2`;
- um owner-device iPhone/iPadOS sob o perfil de telefone, sem participação
  Shamir.

Enrollment de uma terceira máquina ou de N máquinas é diferido. Este contrato
não generaliza `HouseholdRecord.members`, não muda threshold, não cria uma
cerimônia N-machine e não amplia M1 para múltiplos telefones por inferência.

## 3. Grounding factual no objeto-base

### 3.1 Perfil máquina existente

- `P256PublicKey` é ponto P-256 SEC1 comprimido de **33 bytes**.
- `MachineCert.m_pub` usa esse tipo.
- `verify_against_household_root` verifica o certificado contra a root e
  recompõe `m_id` de `m_pub`.
- `issuer_trust::is_machine_issuer_active` exige cert válido, subject exato e
  `m_id` presente em `HouseholdRecord.members`.
- `directory_devices` é somente overlay de remoção; ausência de entrada não é
  autorização nem rejeição.

Limite relevante: `HouseholdRecord` exige `members.len() == shamir_n`.
`pair_machine` executa a transição fixa 1→2, divide a root em 2-of-2 e grava
`shamir_k=2`, `shamir_n=2`. Portanto, `members` é membership de máquinas
participantes da custódia, não roster genérico de endpoints.

### 3.2 Perfil telefone ainda não implementado

`docs/household-protocol.md` já define conceitualmente:

- `PersonCert`, assinado pela HouseholdRoot;
- `DeviceCert`, assinado pela chave da pessoa;
- a cadeia
  `device PoP → DeviceCert → PersonCert → HouseholdRoot`;
- eventos `device_added` e `revocation`;
- snapshot durável de people, devices e CRL.

O runtime atual não realiza esse contrato completo:

- não há tipo Rust `DeviceCert`;
- `handlers_device_pairing` recebe `device_cert_cbor` como bytes opacos;
- só verifica que o blob é não vazio e tem no máximo 64 KiB;
- guarda o resultado em `Arc<Mutex<...>>`, sem persistência;
- não valida assinatura, subject, caveats, PoP ou cadeia;
- não publica autoridade durável de device nem CRL vivo.

Esse handler e seu store não satisfazem R0a.

### 3.3 Lacuna comum atual

Não há hoje uma autoridade runtime atômica que forneça, no mesmo snapshot:

- household root vigente;
- certificado e subject vigentes;
- membership/admission vigente;
- generation não zero;
- cursor/digest de revogação vivo.

Também não há sink de produção que aceite exclusivamente o fato tipado R0a.

## 4. Resultado tipado comum

Nome do contrato: `HouseholdMeshPeerAdmissionV1`.

É uma capability server-local, opaca e consumível uma vez. Não é formato de
wire nem configuração serializável.

Ela carrega, no mínimo:

- versão do contrato;
- perfil: `Machine` ou `OwnerDevice`;
- household id verificado;
- subject id verificado (`m_id` ou `d_id`);
- full point `peer_identity_pub_sec1: [u8; 33]`;
- digest canônico do certificado de subject;
- digest/identidade da cadeia intermediária, quando houver;
- digest da HouseholdRoot usada na validação;
- generation não zero da autoridade de admissão;
- cursor e digest do snapshot de revogação;
- instante lógico da verificação;
- limite efetivo de validade, quando existir;
- digest do snapshot atômico do qual os fatos foram lidos.

O tipo:

- não possui construtor público a partir de input;
- não implementa `Default`, `From` ou `TryFrom` para tipos não confiáveis;
- não é `Serialize`/`Deserialize`;
- não é clonável para multiplicar autorização;
- não expõe raw cert como substituto;
- é produzido somente pelo verificador R0a;
- é aceito somente por sink tipado R0a.

## 5. Invariante de chave — full SEC1 33 bytes

Nos dois perfis, a chave admitida é o ponto P-256 SEC1 comprimido completo:

- comprimento exatamente 33 bytes;
- prefixo SEC1 exatamente `0x02` ou `0x03`;
- ponto válido na curva P-256;
- subject e PoP ligados aos mesmos bytes;
- paridade preservada.

É proibido:

- truncar para x-only 32 bytes;
- descartar ou inferir o byte de paridade;
- converter entre P-256 e P-256K/secp256k1;
- hashear uma chave para fabricar igualdade;
- aceitar chave uncompressed de 65 bytes como representação alternativa;
- promover `baseMeshPublicKeyHex`, IP, subnet, hint, label ou parse success;
- criar chave paralela sem binding assinado e nova decisão versionada.

P e -P possuem a mesma coordenada x. Logo x-only é uma transformação 2:1 e
não é codificação lossless do subject certificado.

## 6. Perfil Machine

Inputs mínimos:

- `HouseholdRecord` corrente;
- `MachineCert` corrente;
- full `m_pub` SEC1 33B;
- snapshot vivo de admission/revoke para máquina.

Verificação cumulativa:

1. validar forma e CBOR canônico do `MachineCert`;
2. exigir `cert_type == Machine`;
3. exigir household e `issued_by` iguais à household esperada;
4. derivar `m_id` de `m_pub` e exigir igualdade exata;
5. executar `verify_against_household_root` contra a root corrente;
6. exigir os mesmos 33 bytes em cert, PoP e peer identity;
7. exigir `m_id` nos dois members atuais;
8. exigir generation de admissão não zero e corrente;
9. consultar revogação viva; ausência de fonte é falha;
10. rejeitar qualquer remoção, generation stale ou snapshot divergente;
11. selar o resultado com os digests e cursor observados.

Para R0a, a assinatura do cert e `members` não bastam sem revogação viva.
O parâmetro opcional `projection=None` aceito por
`is_machine_issuer_active` em outros domínios não é suficiente neste sink.

`MachineCert` v1 não tem `not_after`. Seu lifetime R0a termina quando muda
qualquer um de: root, membership, generation, revogação ou validade do cert.
Nenhum TTL de certificado é inventado.

## 7. Perfil OwnerDevice

Inputs mínimos:

- HouseholdRoot corrente;
- `PersonCert` corrente do dono;
- `DeviceCert` canônico do telefone;
- PoP do `d_pub`;
- snapshot durável e vivo de device admission/revoke.

Verificação cumulativa:

1. validar forma canônica e schema do `PersonCert`;
2. verificar `PersonCert` contra household id e HouseholdRoot correntes;
3. verificar validade temporal e caveats do `PersonCert`;
4. validar forma canônica e schema do `DeviceCert`;
5. derivar `d_id` de `d_pub` e exigir subject exato;
6. exigir `DeviceCert.p_id == PersonCert.p_id`;
7. exigir `DeviceCert.issued_by == PersonCert.p_id`;
8. verificar assinatura do `DeviceCert` contra `PersonCert.p_pub`;
9. provar que os caveats do device são iguais ou mais restritivos que os da
   pessoa;
10. verificar PoP do `d_pub` com challenge domain-separated de R0a;
11. exigir entrada ativa e exatamente correspondente na autoridade durável;
12. exigir generation não zero e snapshot de revogação corrente;
13. rejeitar pessoa ou device revogados, expirados, stale ou divergentes;
14. selar o resultado com todos os digests e cursor observados.

O perfil não converte o telefone em máquina. `d_id`, `d_pub`, `DeviceCert` e
seu estado durável permanecem fora de `members`, Shamir e
`is_machine_issuer_active`.

Monotonia de caveat não é uma asserção booleana do caller. O verificador:

- interpreta todas as operações e constraints conhecidas;
- exige que toda operação do child exista no parent;
- exige scope e conjuntos do child iguais ou subconjuntos do parent;
- exige expiry do child menor ou igual ao limite efetivo do parent;
- rejeita caveat ou constraint desconhecido;
- sela o digest da prova de narrowing no fato produzido.

## 8. D2 — home durável e autoridade viva (ADOTADO)

### D2: `HouseholdDeviceAdmissionAuthorityV1`

O home lógico do perfil telefone é um objeto durável, generationed e atômico
da identidade da household, separado de:

- `DevicePairingStore` efêmero;
- `directory_devices`;
- estado DP2/owner-site;
- rendezvous;
- configuração do túnel.

D2-B adotada: o home usa **store owner-mesh próprio**. Ele não reutiliza
`MeshLogStore`, schema, autoridade ou semântica de Product A/claw-share.
Qualquer integração futura com `MeshLogStore` exige autorização humana
explícita, diretiva versionada e review de fronteira.

`DirectoryDeviceAdded`/`DirectoryDeviceRemoved` atuais não bastam:

- carregam apenas `device_pub` e label/remoção;
- não carregam `DeviceCert`, `PersonCert`, digests, `p_id` ou generation;
- `LogEntry::verify` prova integridade sob `issuer_pub`, não que o issuer tinha
  autoridade para emitir o evento;
- a projeção atual dobra entradas antes de uma prova R0a do issuer;
- o próprio código documenta essa lacuna de autorização em replicação.

Logo `directory_devices` permanece overlay/kill-switch. Ele pode negar, mas
não produzir `HouseholdMeshPeerAdmissionV1`. Uma remoção ali é deny adicional;
presença ou ausência nunca admite. O evento R0a próprio só entra no store
depois de validar issuer, cadeia e generation.

O snapshot lógico contém:

- household id e digest da HouseholdRoot;
- generation monotônica e não zero;
- mapa `d_id → {d_pub_sec1, device_cert_digest, p_id,
  person_cert_digest, status}`;
- cursor/digest de revogação;
- status de revogação de pessoa e device;
- digest canônico do snapshot inteiro.

Regras adotadas:

- add/revoke é mutação explícita, autenticada e auditável;
- cada evento é autorizado antes da persistência/projeção, não apenas
  autoassinado;
- publicar device exige `DeviceCert` já validado contra `PersonCert`;
- a operação de device é distinta de `HouseholdAddMachine`;
- cada add/revoke incrementa generation;
- persistência e generation mudam atomicamente;
- crash/replay não pode reabrir device removido;
- revoke vence add concorrente ou tardio;
- consumers leem um snapshot, nunca campos de stores independentes;
- ausência do objeto, generation zero ou cursor desconhecido falha fechado.

### D2-A — autoridade de mutação (ADOTADA)

Add:

- exige owner `PersonCert` vigente;
- exige PoP fresco e domain-separated **para cada ADD**;
- exige operação própria add-device, nunca `HouseholdAddMachine`;
- exige `DeviceCert` assinado pela chave da pessoa e validado integralmente;
- o device novo nunca assina a própria admissão.

Revoke:

- o owner `PersonCert` vigente pode revogar device descendente;
- um device pode self-revogar somente seu próprio `d_id`, provando posse do
  mesmo `d_pub`;
- self-revoke não pode adicionar device, revogar sibling, revogar pessoa,
  revogar máquina ou ampliar caveats;
- replay de self-revoke é idempotente e nunca reabre admission;
- revogação da pessoa revoga todos os devices descendentes.

Em ambos:

- a HouseholdRoot continua sendo a única root de confiança, pois valida o
  `PersonCert`;
- a chave da pessoa assina o `DeviceCert`;
- revogar é fail-safe e não concede nova autoridade.

O path físico, encoding de persistência e nomes de endpoints ficam para uma
diretiva de implementação posterior. Eles não podem alterar a autoridade
lógica acima.

## 9. D3 — relação entre subject key e peer identity (ADOTADA)

### D3: direct subject-key para v1

Regra adotada:

- perfil máquina:
  `peer_identity_pub_sec1 == MachineCert.m_pub`;
- perfil telefone:
  `peer_identity_pub_sec1 == DeviceCert.d_pub`;
- igualdade byte a byte sobre os 33 bytes SEC1;
- PoP prova posse da mesma chave;
- nenhuma segunda chave de peer é introduzida.

Racional:

- é a forma menor e mais auditável;
- evita uma segunda autoridade de binding;
- evita key lookup paralelo;
- preserva o full point certificado;
- produz o mesmo tipo selado nos dois perfis;
- mantém R0a independente do túnel e do rendezvous.

`peer_identity_pub_sec1` é identidade de admissão. Este contrato não manda T1
usar a chave como Noise static key nem altera handshake, framing ou pump.

### D3-B futuro — exige nova decisão e review

Se uma camada futura exigir chave de transporte diferente, a igualdade direta
não pode ser substituída por conversão ou hint. Será necessário um
`MeshPeerKeyBinding` explícito, domain-separated, assinado pelo subject
autorizado e coberto pela mesma generation/revogação. Isso é nova decisão de
identidade/autoridade, com versão e review próprios.

Se uma fatia futura tentar usar `peer_identity_pub_sec1` como Noise static key,
ela deve parar e receber review específico do acoplamento
identidade-transporte. D3 não autoriza esse uso.

## 10. Snapshot vivo, generation e consume-time fence

O verificador lê um único snapshot lógico atômico. Ele não compõe autoridade
misturando leituras independentes de root, cert, roster e revoke.

No consume:

1. receber a identidade exata do peer que o dial pretende alcançar;
2. exigir igualdade byte a byte entre essa identidade e
   `admission.peer_identity_pub_sec1`;
3. impedir que fato selado para peer A autorize peer B, mesmo se endpoint,
   label, IP ou hint coincidirem;
4. reler a autoridade viva imediatamente antes do efeito;
5. exigir a mesma root;
6. exigir os mesmos cert digests e subject;
7. exigir a mesma generation não zero;
8. exigir o mesmo cursor/digest de revogação;
9. revalidar lifetime;
10. consumir a capability e a identidade exata no mesmo ponto atômico que
    autoriza o efeito.

Qualquer mudança ou impossibilidade de leitura produz zero efeito. Cache
anterior a nova generation é inválido e não pode ser refreshed parcialmente.
O sink não pode descartar `peer_identity_pub_sec1` nem substituí-lo por target,
endpoint ou decisão anterior do router.

## 11. Seam inert-complete

R0a v1 deve poder ser construído e provado antes de existir wiring de
produção:

- tipos e verificadores compilam em produção;
- sink tipado compila em produção e rejeita qualquer substituto;
- nenhuma fonte de produção é instalada por este contrato;
- seam de teste injeta snapshots completos, nunca campos avulsos;
- testes exercitam producer → capability → sink;
- produção sem provider continua inalcançável e fail-closed;
- harness de teste não é autoridade de produção;
- nenhum setter, route, adapter ou provider é criado por inferência.

Inert-complete significa maquinaria completa e testável, não efeito runtime.

## 12. Matriz negativa mínima

### Comum

- SEC1 com 32, 34 ou 65 bytes;
- prefixo inválido, ponto inválido ou curva errada;
- x-only com paridade ausente;
- subject id divergente da chave;
- PoP de outra chave;
- root errada ou alterada;
- generation missing, zero, stale ou alterada;
- cursor/digest revoke ausente ou divergente;
- snapshot não atômico;
- cache anterior a mutation;
- raw cert, raw key, bool, hint, IP/subnet ou parse success no sink;
- fato selado para peer A apresentado ao dial de peer B;
- sink que ignora ou substitui `peer_identity_pub_sec1`;
- bypass do producer ou consume-time recheck;
- TOCTOU entre verify e efeito;
- falha sempre produz zero efeito.

### Machine

- cert assinado por root estrangeira;
- household ou issuer divergente;
- `m_id` fora de `members`;
- terceiro machine id no escopo v1;
- device colocado em `members`;
- projection de revogação indisponível;
- machine removida após verify.

### OwnerDevice

- CBOR opaco não tipado;
- PersonCert expirado, revogado ou de outra household;
- DeviceCert assinado por outra pessoa;
- `p_id`, `d_id` ou `d_pub` divergente;
- caveat de device mais amplo que o parent;
- caveat/constraint desconhecido ou narrowing apenas afirmado;
- scope, conjunto ou expiry do child fora do limite do parent;
- device ausente do home durável;
- device ou pessoa revogados;
- store somente em memória;
- presença em `directory_devices` usada como allow;
- dependência de `MeshLogStore` sem autorização de integração;
- add sem PoP owner fresco ou com replay de PoP anterior;
- self-revoke de sibling, pessoa ou máquina;
- tentativa de usar `HouseholdAddMachine`;
- tentativa de produzir machine issuer;
- tentativa de alterar Shamir;
- revoke seguido de replay de add.

## 13. Não objetivos e fronteiras

R0a não:

- modifica R0b ou seu R2;
- escolhe discovery, rendezvous, relay, STUN ou Nostr;
- modifica T1, Noise, framing, pump ou packet filter;
- modifica router, ACL, route allocation ou target model;
- ativa Packet Tunnel/Network Extension;
- escolhe provider ou infraestrutura;
- implementa enrollment N-machine;
- abre Product A/nvpn ou importa suas premissas;
- persiste endpoint de rede;
- cria produção por consequência do review.

Se realizar R0a exigir mudar handshake/pump ou reutilizar autoridade de outro
produto, a implementação para e escala.

## 14. Gates antes de implementação

1. review de segurança Safia ligado ao novo raw SHA deste documento;
2. review funcional independente, incluindo prova de narrowing de caveats;
3. diretiva de implementação separada com repositório, paths e base exatos;
4. inventário do head persistente usado pela implementação;
5. testes negativos individuais e guard de set-coverage;
6. review SHA-bound do futuro head, incluindo binding ao peer exato;
7. pin/reâncora e boundary Phase-0 conforme os paths reais;
8. ativação em fatia posterior e separadamente autorizada.

Nenhum gate documental autoriza automaticamente o seguinte.

## 15. Referências pinadas no objeto-base

Objeto:

- `c106fc1ffd1cf8d3af269dcbbd029f62c87cda8b`.

Blobs:

- `admin/rust/household-rs/src/household_record.rs`
  `a885f367d7659ac1914aaea35269814d882abb5c`;
- `admin/rust/household-rs/src/pair_machine.rs`
  `ddf648ac5676fb8559573fca7c487d09af3a631a`;
- `admin/rust/household-rs/src/machine_cert.rs`
  `c2c44b393ecf60900e5c7c16ff6d9557bd24ecc5`;
- `admin/rust/household-rs/src/issuer_trust.rs`
  `db718e1960cadd75247306763105c742dcdfb857`;
- `admin/rust/household-rs/src/household_mesh_log.rs`
  `44fee3d933759e909de0a0be0400c5651295fef1`;
- `admin/rust/server-rs/src/handlers_device_pairing.rs`
  `b81fd8494fb42b7eee801d9acae9cd9bf160642d`;
- `docs/household-protocol.md`
  `3b7b6ee7f39838333786bf0a615ca9c0e3730339`;
- `docs/owner-mesh-rendezvous/r0b-protocol-contract-v1.1-final.md`
  `9fc0476e5f3834671941eda8b7d827e7c146ea36`;
- `docs/owner-site-a2-dataplane/dp2-pendingfinished-a2-bridge-contract-v1.2.md`
  `1b9140d74cab468fa25ae27c310841f3a9dbe6d0`.

## 16. Estado de fechamento

Fixado por decisão humana:

- D1 dual-chain;
- D4 M1 mínimo: Mac + Linux no par atual e telefone fora de Shamir.
- D2 home durável, generationed e atômico;
- D2-A owner `PersonCert` com PoP por add e self-revoke escopado;
- D2-B store owner-mesh próprio;
- D3 direct subject-key byte a byte.

Até os reviews e gates §14:

- R0a é contrato canônico sem autorização de implementação;
- o STOP pré-código permanece;
- a produção continua não-wired;
- nenhum efeito é autorizado.
