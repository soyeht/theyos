# R0a Household Mesh Peer Admission — reâncora factual

Status: **registro documental de reâncora; sem autorização de código,
ativação, ARM, reseal ou merge**.

Data: 2026-07-25.

## 1. Objeto reancorado

Contrato canônico persistido byte-exato neste candidato:

- path:
  `docs/owner-mesh-rendezvous/r0a-household-mesh-peer-admission-contract-v1.md`;
- raw SHA-256:
  `031f46a583b94c0b2531305501248b3f4d2be0fa550558fbbe4bbc090dd996ae`;
- git blob:
  `30fcfcbbc4a05a145579511b8fbba5c70d67e656`;
- `20496` bytes, `539` linhas;
- último byte: `0x0a`.

Esses são os mesmos bytes ligados aos reviews de segurança e funcional do
contrato. O contrato não foi reformatado, normalizado ou editado para atualizar
seus pins históricos.

Diretiva documental relacionada, ainda externa a este candidato:

- `DD-R0A-HOUSEHOLD-MESH-PEER-ADMISSION-IMPL-1`;
- raw SHA-256:
  `9e9f0d7fa53a7b7615fdeaae7a014fe727783b0142a79e29668a8ff74c39ab4d`;
- `28923` bytes, `801` linhas.

Este registro não persiste nem adota a diretiva de implementação.

## 2. Parent atual

Reâncora calculada contra:

- repositório: `soyeht/theyos`;
- commit:
  `be8418ee16043991a533ca00019cfd053f55c049`;
- tree:
  `b8c9422b015534162b7dbab4b8dc4f2a62f8b53f`.

O `origin/main` local e o `main` remoto foram verificados no mesmo commit antes
da criação do candidato.

## 3. Pins do contrato no parent atual

Sete dos nove blobs do §15 do contrato permanecem byte-idênticos:

| Path | Blob atual |
|---|---|
| `admin/rust/household-rs/src/household_record.rs` | `a885f367d7659ac1914aaea35269814d882abb5c` |
| `admin/rust/household-rs/src/machine_cert.rs` | `c2c44b393ecf60900e5c7c16ff6d9557bd24ecc5` |
| `admin/rust/household-rs/src/issuer_trust.rs` | `db718e1960cadd75247306763105c742dcdfb857` |
| `admin/rust/household-rs/src/household_mesh_log.rs` | `44fee3d933759e909de0a0be0400c5651295fef1` |
| `admin/rust/server-rs/src/handlers_device_pairing.rs` | `b81fd8494fb42b7eee801d9acae9cd9bf160642d` |
| `docs/owner-mesh-rendezvous/r0b-protocol-contract-v1.1-final.md` | `9fc0476e5f3834671941eda8b7d827e7c146ea36` |
| `docs/owner-site-a2-dataplane/dp2-pendingfinished-a2-bridge-contract-v1.2.md` | `1b9140d74cab468fa25ae27c310841f3a9dbe6d0` |

Correção dos dois pins restantes:

| Path | Pin histórico | Blob atual |
|---|---|---|
| `admin/rust/household-rs/src/pair_machine.rs` | `ddf648ac5676fb8559573fca7c487d09af3a631a` | `473169533094982c554aa5dd4ec3374eb5d114b7` |
| `docs/household-protocol.md` | `3b7b6ee7f39838333786bf0a615ca9c0e3730339` | `a0fc91e22b2fe9da81b0e081f1d696bb363cc425` |

Esses dois paths acumulam três eventos factuais de deriva:

1. `docs/household-protocol.md` mudou de `3b7b6ee7` para `8ec65987`
   ao estreitar “todos os endpoints usam CBOR” para “endpoints de controle
   usam CBOR” e documentar o diagnóstico de reachability/echo como exceção
   explícita `application/octet-stream`;
2. o mesmo documento mudou de `8ec65987` para `a0fc91e2` no `#394`,
   documentando `x-soyeht-candidate-tailscale-addr` como hint pós-Ready
   unsigned e não autoritativo, sem alterar o CBOR determinístico de
   `FinalizeAck`;
3. `pair_machine.rs` mudou de `ddf648ac` para `47316953` no `#394`,
   adicionando a constante desse header e
   `FinalizeWithM2Outcome::candidate_tailscale_addr` fora de `FinalizeAck`,
   exposto somente após os checks de versão, machine-id e cert-hash do ACK.

O delta de `pair_machine.rs` não altera `issue_for_candidate`, `new_members`,
`members`, Shamir, `MachineCert` ou `is_machine_issuer`; a única menção nova a
membership proíbe usar o hint como autoridade. Os três eventos não alteram
caveat narrowing, DeviceCert, raiz, generation, revoke ou admissão de peer.

## 4. Pins adicionais usados pela diretiva

Permanecem byte-idênticos ao inventário da diretiva:

| Path | Blob atual |
|---|---|
| `admin/rust/household-rs/src/keys.rs` | `f29ce9c2beeb9d1bac272095cd0c8b0104651864` |
| `admin/rust/household-rs/src/person_cert.rs` | `367f0cd81419d31823961bdddbd1a661e98235c0` |
| `admin/rust/household-rs/src/caveats.rs` | `3d847d54950d31ee99376cda8136f05c34735583` |
| `admin/rust/household-rs/src/chain.rs` | `d46749d126e361b1a73a6e3d6aedcf4e0324671f` |

`admin/rust/household-rs/src/storage.rs` mudou de
`f132efe7d4dffd1058557ac3f0e45f1659f7aa8c` para
`dd451cf596bf399f4222d58e743114b6a1c08929`. O delta adiciona somente o cache
best-effort `m_id -> addr` e seus testes. Ele reutiliza os mesmos primitivos
existentes de leitura CBOR e escrita atômica; não altera `atomic_write_cbor`,
permissões `0600`, `fsync`, rename, canonicalização ou autoridade R0a.
Ele adiciona um writer e seu read-modify-write do mapa completo não é
serializado; writers concorrentes podem perder uma dica. Essa perda retorna à
ausência/`unknown`, direção fail-closed, e não transforma o cache em autoridade.

Essa classificação é factual. A futura Fatia S ainda deve inventariar o parent
persistente e provar seus próprios paths, negativos e guards.

## 5. Boundary e protected objects

No parent atual:

- boundary 8/8:
  `admin/contracts/mobile-claw-vpn/v1/owner_present_phase0_artifact_boundary_v1.tsv`,
  blob `e54fb9f3f7bfad9d7203e2d332fb6fbe25de34c5`;
- tree `admin/rust`:
  `5aceba6ee598c01c806c700218cb77dd0d7f8d69`;
- protected-object policy:
  `.github/owner-present-phase0-protected-objects-v1.tsv`,
  blob `5282959b080d4e1a86f2682cd4df798663e6cc29`;
- transition:
  `.github/owner-present-phase0-transition-v1.json`,
  blob `e1a446d70c7d1ce6171a944cb431d5dfec6249db`.

Em relação ao parent anterior `c8e5f9556217f1daedafdff2782728810a23ee56`,
o `main` avançou por `b123d2861984a5f8c7c4617a9eebeca1d34d92fa`
(`#397`) e `be8418ee16043991a533ca00019cfd053f55c049` (`#394`).
O `#397` altera `handlers_claw_share.rs` e reseala `admin/rust`, mas move zero
dos nove pins do §15. O `#394` move somente os dois pins declarados no §3
acima e reseala novamente `admin/rust`. Os quatro pins adicionais da diretiva,
policy e transition permanecem byte-idênticos.

Este candidato adiciona somente dois arquivos em
`docs/owner-mesh-rendezvous/`. Ele não intersecta nenhuma das oito raízes
fechadas, nenhum protected object e nenhum path de policy ou transition.
Portanto não exige reseal, ARM ou consume.

## 6. Limites

Esta reâncora:

- não modifica os bytes canônicos `031f46a5`;
- não adota a diretiva `9e9f0d7f`;
- não autoriza Fatia N ou qualquer código;
- não escolhe nem implementa D3-B;
- não decide autorização device-device;
- não cria provider, wiring, endpoint, router, ACL, T1 ou datapath;
- não abre Product A/nvpn;
- não autoriza merge ou ativação.

Qualquer implementação futura parte de um parent persistente re-verificado e
segue os gates seriais do contrato e da diretiva.
