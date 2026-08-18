# Soyeht — plano de construção do mesh

**v5 — executável.** Substitui a v4 congelada (`soyeht-plano.md`), que pressupunha
um datapath WireGuard que não existe e não vai ser construído.

**Bancada:** `host-alpha` (Linux, sempre ligado, host das VMs) · `desktop-alpha` ·
`laptop-alpha` · `device-alpha` (telefone). Aliases neutros de propósito: nome de
máquina, hostname de SSH e nome de device são identificadores de infraestrutura
pessoal e não entram em documento versionado.

---

## A decisão que gerou esta versão (medida 2026-08-18 @ `6bd13fe3`)

<!-- doc-freshness-anchor
measured: 2026-08-18
sha: 6bd13fe3679138248355205b15356b4bdaaeb0f2
paths:
  - admin/rust/mesh-session-core-rs/**
  - admin/rust/mesh-session-control-model-rs/**
  - admin/rust/server-rs/src/claw_vpn_*
  - admin/rust/t1-iptunnel-dev-runner-rs/**
  - admin/rust/nat-probe-rs/**
  - admin/rust/scripts/graph-gate/**
  - admin/rust/scripts/backend-rust
  - scripts/noise-conformance-peer.py
  - .github/workflows/backend-ci.yml
-->


A v4 especificava um datapath WireGuard do zero: `boringtun`, os tipos
`PacketCrypto` / `WireGuardDevice` / `SoyehtBind`, e um teste de interoperação
com o `wg` do kernel no M1.

**Recusado, 2026-08-08.** Duas auditorias independentes do `theyos` acharam zero
WireGuard/boringtun no repositório. O que existe é um stack Noise próprio, com
cobertura de teste real:

| Camada | Onde | Estado |
|---|---|---|
| Sessão segura (Noise XX, "B-SESSAO") | `mesh-session-core-rs` | maduro |
| Framing, pump, rota escopada | `tunnel-wire-rs` | maduro |
| Identidade, roster, revogação, WebAuthn | `household-rs` | maduro |
| TUN Linux / utun macOS | `server-rs/src/claw_vpn_{linux_tun,macos_utun}.rs` | real, atrás de gate |
| Sessão IpTunnel real (auth, IP, MTU) | `t1-iptunnel-dev-runner-rs` | real, atrás de gate |

Nada disso está em produção, então o custo de migração era zero **nos dois
sentidos** — foi essa simetria que fez a cobertura de teste decidir. O único
argumento da v4 para WireGuard era o teste de interop com `wg`.

**Não existe requisito de produto para falar com peer, roteador, cliente ou
servidor WireGuard de terceiro.** A releitura de M2–M12b confirmou: a única
interoperação WireGuard do plano inteiro era o M1, usado como *oráculo de
implementação*, não como funcionalidade entregue. Se um dia aparecer subnet
router / exit node / peer externo, é requisito novo e decisão nova.

### O que substitui o oráculo do `wg`

O teste do `wg` existia por um motivo correto, que a v4 enuncia melhor do que
qualquer outra linha do documento: **dois programas seus concordando não provam
nada.** Isso continua valendo, e o TUN/utun real **não** o satisfaz — as duas
pontas são código nosso, então é prova de *integração*, não de *independência*.

O substituto é conformance do protocolo contra uma segunda implementação:

1. Congelar vetores do protocolo exato: prologue, os 3 flights XX com payload
   vazio, transcript/handshake hash, e os primeiros records de transporte nos
   dois sentidos.
2. Verificar esses vetores com **outra implementação Noise, em outra linguagem,
   que não compartilhe crypto nem estado com o `snow`**. O glue pode ser nosso;
   a implementação criptográfica não.
3. Vetores byte-a-byte Rust↔Swift da camada Soyeht: length framing, CBOR
   canônico, intent/auth frames, DATA/CLOSE/REKEY, e as negativas (length
   excessivo, CBOR não canônico, assinatura/nonce/epoch/previous_hash alterados).
4. Negativas de replay, reorder, bit flip, peer/cert errado, grant
   expirado/revogado e fronteira de rekey.

Isso vira **M1a** (conformance) e **M1b** (wire/auth cross-language), e é o
começo do caminho crítico.

---

## Ordem de execução

O caminho crítico deixou de ser a sequência numérica.

Arestas reais, não agrupamento visual:

```
M1c                  → M1a + M1b        (sem CI, nada acima é evidência)
M1a + M1b            → M2
M2                   → M3
M3                   → M4
M3 + M8              → M5
M3 + M5 + M6         → M7
M5 + M6 + M7 + M8    → M11
M3 + M4 + M5         → M12a → M12b-0 (congela o SLO) → M12b
M7                   → fechamento E2E do M10
```

**Lane B — M6, M8, M9 e o core do M10 — roda em paralelo e NÃO converge toda em
M2.** M6 e M8 alimentam M5/M7/M11 mais tarde; M9 e o core do M10 não são
pré-requisito de marco de datapath nenhum.

- **M6, M8, M9 e o core do M10 não implementam datapath** e podem começar já,
  em paralelo com a Lane A.
- **M11 não adiciona datapath**, mas seu E2E depende do datapath integrado.
- **M12b não vem antes do M12a** e de um contrato explícito de reconnect/resume.
- **M10** fecha o core sem datapath; só o "device remoto acessa a UI" espera M7.

---

## Promoção do gate `dev_t1_datapath`

O datapath real existe e está deliberadamente compilado fora de produção, com
os próprios módulos documentando *"intentionally not wired into bootstrap, bins,
relay runtime, route installation, storage, or flags"*.

**Isso permanece fechado.** Sair do gate é um marco com aprovação acordada, nunca
efeito colateral de outra entrega. Exige, em revisão separada:

- **M1c verde** — cobertura que não executa em automação não é evidência de
  promoção, por mais madura que seja;
- conformance independente (M1a/M1b) passando;
- TUN/utun real + relay E2E;
- tamper / replay / revoke / route-scope todos fail-closed;
- limites de frame, fila e memória exercitados sob peer lento;
- nenhuma regressão dos gates de compile-out / protected-object.

Até lá, **"pronto" significa evidência de dev/harness, nunca produção.**

---

## M0a — Probe de NAT · ENTREGUE (código), amostras incompletas

Telemetria para decidir onde colocar relay. Roda em paralelo, não bloqueia nada.

`nat-probe-rs` (lib + bin `nat-probe`). STUN RFC 5389 escrito à mão, duas
famílias de endereço, **um socket por família** — o invariante "mesmo socket"
vale dentro de uma família; comparar mapping v4 com v6 não significa nada.

Grava tudo, nunca um veredito. **Não existe campo `direct_possible`**, e um teste
falha se alguém adicionar um: RFC 5780 §2 separa mapping de filtering e diz que
ambos são observação momentânea. `mapping_consistent` é `Option<bool>` —
`None` (um servidor calou) é diferente de `Some(false)` (mediu e divergiu).

**Pronto quando:** 5+ linhas com todos os campos preenchidos.

| vantagem | estado |
|---|---|
| `desktop-alpha` / ethernet | ✅ |
| `device-alpha` / wifi | ✅ |
| `device-alpha` / rede móvel | ❌ aparelho sem dado celular (linha/plano) |
| `host-alpha` / ethernet | ❌ host de laboratório temporariamente inalcançável |
| `laptop-alpha` / wifi doméstico · wifi público | ❌ precisa de acesso físico |

Duas lições que ficaram no código:

- **21 testes offline passaram enquanto zero pacotes saíam da máquina.** Socket
  v4 + `to_socket_addrs()` devolvendo o AAAA primeiro = `EINVAL` em todo envio.
  Nenhum teste alcançava a escolha do destino, o único passo sem entrada nossa.
- **Toda linha grava `tunnel_interfaces`.** Duas amostras de campo foram tiradas
  com uma VPN de produção conectada e ninguém checou. A validade delas teve que
  ser provada depois, comparando o IP público observado com o de outro host atrás
  do mesmo NAT. Agora a linha se autodescreve.

---

## M0b — Smoke de provisioning iOS

**Objetivo:** descobrir o inferno de provisioning agora, não no M4. Ortogonal ao
datapath — não depende de nada nesta lista e não bloqueia nada.

Não implemente VPN nenhuma. Suba uma extensão mínima que carrega e lê um valor.

**Construir e validar:** entitlement de Network Extension
(`packet-tunnel-provider`) · App Group compartilhado entre app e extensão ·
Keychain Access Group compartilhado · XCFramework Rust carregando **dentro da
extensão**, não só no app.

**Teste, no aparelho físico e não no simulador:**
1. o app grava um canary no Keychain (access group compartilhado);
2. a extensão sobe, lê o canary e loga;
3. a extensão chama uma função Rust trivial do XCFramework;
4. bloquear o aparelho e repetir 2 e 3.

**Pronto quando:** os quatro passos funcionam no aparelho real.
**Estado:** 1–4 provados em aparelho físico. **M0b FECHADO** — o passo 4 foi
medido de verdade em 2026-08-10, sem debugger/XCTest/USB anexado (ver "O passo
4 foi resolvido" abaixo); a seção logo depois documenta a medição anterior,
inválida, e por que ela não podia ser usada.

> Bloqueio conhecido: o primeiro save de uma `NETunnelProviderManager` nova pede
> o passcode físico do aparelho. É gate humano, não bug — não dá para automatizar
> em torno dele.

### O passo 4 foi resolvido: medição real, sem contexto anexado, 2026-08-10

A correção não foi isolar qual componente do contexto anexado causava o
problema (debugger, XCTest, USB) — foi removê-lo por inteiro, como a seção
abaixo já apontava que seria necessário. Solução: o app host (soyeht-ios)
ganhou um gatilho `soyeht://debug/m0b-lock-canary-start?delaySeconds=N`
(Dev-only, `#if DEBUG`) que só prepara os itens de Keychain e chama
`startVPNTunnel` — a leitura de verdade acontece **dentro da extensão**,
numa `Task.detached` que dorme `N` segundos antes de ler, porque um
`NEPacketTunnelProvider` que já reportou "conectado" é o tipo de processo
em background que o iOS mantém vivo, ao contrário do app host, que seria
suspenso ao travar a tela. Fluxo: instalar via `devicectl` (nunca
`xcodebuild test`/Xcode Run, que sempre anexam), abrir o link pelo app
Notas (evita a barra de endereço do Safari tratar o esquema customizado
como busca), travar o aparelho na hora, esperar, e ler o resultado depois
por `devicectl device copy from --domain-type appGroupDataContainer` — sem
tocar no aparelho de novo durante a janela medida.

Resultado real, aparelho travado de verdade, sem nada anexado:

```
whenUnlockedStatus       -25308   (errSecInteractionNotAllowed — correto)
afterFirstUnlockStatus   0        (errSecSuccess — correto, prova a premissa do M4)
whenPasscodeSetStatus    -25308   (errSecInteractionNotAllowed — correto)
protectedFileReadable    false    (keybag genuinamente travado — ao contrário da medição inválida abaixo)
trigger                  "delayed"
```

O observável independente (`protectedFileReadable`) virou `false` desta
vez — era `true` na medição inválida abaixo mesmo com o aparelho travado, e
é exatamente esse observável que prova que agora o keybag travou de
verdade. Os três `kSecAttrAccessible*` bateram com o esperado. A premissa
do M4 (reconexão em background sobrevive o aparelho travado, via
`AfterFirstUnlockThisDeviceOnly`) está provada, não assumida.

Medido por @gianna com @Caio travando o aparelho fisicamente no momento
certo — a parte que nenhuma automação podia fazer sem reintroduzir o
mesmo contexto anexado que invalidou a primeira medição.

### O passo 4 não era executável no contexto de teste anexado que foi medido primeiro (histórico)

**O que foi medido, e só isso:** sob XCTest/Xcode anexado via USB, os dados
protegidos permaneceram **disponíveis** apesar do bloqueio físico do aparelho.
Medido em 2026-08-09, tela apagada, botão apertado, janela de 45,7 s cronometrada:

```
isProtectedDataAvailable   true      (host)
protectedFileReadable      true      (extensão)
```

**A CAUSA NÃO FOI ISOLADA.** O contexto medido tem pelo menos quatro variáveis
juntas — debugger anexado, XCTest, cabo USB, e a combinação delas — e nenhuma foi
variada isoladamente. Este documento afirma a **correlação medida**, não o
mecanismo. Quem for atacar isso não deve começar assumindo qual componente é o
responsável.

Consequência prática, e é a parte que engana: **qualquer canary de Keychain passa
nesse contexto**, porque a proteção não está ativa. Uma leitura bem-sucedida de um
item `WhenUnlockedThisDeviceOnly` com o aparelho travado é sinal de **instrumento
inválido, não de acessibilidade correta**. Três tentativas foram gastas antes
disso ficar claro, todas devolvendo `0/0/0` de forma perfeitamente consistente
com um keybag aberto.

**Não infira o estado do keybag a partir de uma leitura de Keychain.** Observe-o
direto: `isProtectedDataAvailable`, ou um arquivo com `NSFileProtectionComplete`
cuja leitura deve falhar. São os observáveis em que o invariante está escrito; a
leitura de Keychain funde keybag destrancado, atributo errado e caminho não
modelado num único resultado.

**O que o passo 4 exige:** remover o **contexto inteiro**, não um componente
escolhido por palpite — app instalado, harness já vivo fazendo polling, **sem
XCTest, sem debugger, e USB desconectado**, com o resultado gravado para leitura
posterior. Remover o conjunto responde a pergunta do marco; isolar qual peça
causa o quê é uma investigação separada, e não é o que o M0b precisa.

**Mais `sleep` ou mais repetições no MESMO contexto anexado não agregam
evidência** — três rodadas já devolveram o mesmo resultado com a janela
cronometrada, então o tempo está controlado e não é a variável.

> Esta rodada não é achado de Keychain e não justifica abrir Feedback: o que se
> mediu foi o instrumento, não o comportamento do sistema. Nenhum veredito sobre
> a Apple é afirmado aqui — não temos medição que o sustente.
>
> Achado e medido por @gianna, que recusou três vezes aplicar o "conserto"
> (`AfterFirstUnlock`) por cima de um verde que não media nada — o conserto teria
> fechado o marco, e o furo apareceria só em campo, com a VPN não reconectando
> com o telefone no bolso.

## M1a — Conformance Noise independente

Duas metades, porque exigir "byte-a-byte" de um handshake com chaves frescas é
impossível por construção — e a resposta certa **não** é enfraquecer o core.

**a) Vetores determinísticos, em harness isolado.** Chaves static/ephemeral fixas
de teste, num harness que nunca toca o build de produção.
**Proibido** adicionar `fixed_ephemeral_key_for_testing_only` — ou qualquer seam
de chave fixa — à superfície ou ao fluxo de produção. Hoje o core gera keypair
fresco por conexão e não expõe esse seam; isso é propriedade, não acidente.

**b) Interop ao vivo, com o código de produção.** O endpoint Rust real completa um
handshake contra a segunda implementação, cada lado com chave própria que o outro
nunca viu.

**Construir:** exportador dos vetores (prologue, os 3 flights XX, transcript hash,
primeiros records); verificador numa segunda implementação Noise, em outra
linguagem, sem compartilhar crypto nem estado com o `snow`.

**Pronto quando:** (a) a segunda implementação reproduz os vetores byte-a-byte;
(b) o handshake ao vivo completa e **os dois lados derivam o mesmo handshake
hash**; e as negativas (bit flip, replay, reorder, prologue trocado) falham nos
dois modos.

> **Estado (2026-08-10): M1a ABERTO.** Fechou-se a metade (b), e só ela.
>
> **(b) feito e exigido em automação.** O interop ao vivo está versionado
> como teste do core: `snow` ↔ `noiseprotocol`, prologue e framing reais, cada
> lado com chave própria, hash de handshake idêntico e transporte nos dois
> sentidos. O comparando é **pinado** — `noiseprotocol==0.3.1` — porque numa
> prova de conformidade a implementação externa *é* parte do vetor, e um pin
> flutuante deixa a afirmação mudar de sujeito sem diff no repositório. O teste
> é refusável por `THEYOS_REQUIRE_NOISE_INTEROP`, e essa escotilha existe para o
> laptop sem `uv`, não para o CI.
>
> **Exigido no CI, nos dois runners.** `THEYOS_REQUIRE_NOISE_INTEROP=1` é
> exportado dentro de `phase_excluded_members` em
> `admin/rust/scripts/backend-rust`, o despachante partilhado que a pipeline
> Rust passou a usar; os dois runners invocam essa fase com
> `admin/rust/scripts/backend-rust excluded-members`, e em cada um deles o `uv`
> é instalado **antes** dessa invocação. A declaração é única e partilhada, em
> vez de uma cópia por runner. A ordem é carga estrutural, não arrumação: com a
> ordem anterior o step tomava o ramo "sem uv" e publicava verde sem provar
> nada. Medido nos três modos — peer presente com `REQUIRE` passa; peer ausente
> com `REQUIRE` falha (exit 101); peer ausente sem `REQUIRE` pula, porque a
> escotilha existe para o laptop sem `uv` e não para o CI.
>
> A evidência é **positiva e nominal**, não ausência de aviso: o log de cada
> runner carrega `interop peer: noiseprotocol=0.3.1`, nomeando a implementação
> contra a qual a afirmação foi feita. Ausência da palavra `SKIP` **não** serve
> de prova — o libtest captura o stdout de um teste que passa, então um skip
> bem-sucedido produz log byte-idêntico ao de um handshake real. Por isso o
> `--nocapture` naquele comando é evidência, e removê-lo cega o gate.
>
> **(a) não começou.** Vetores determinísticos em harness isolado, e as
> negativas (bit flip, replay, reorder, prologue trocado) nos dois modos. Sem
> isso o "Pronto quando" acima não está satisfeito, e nenhuma prova de (b) o
> substitui: uma implementação que concorda com a nossa não demonstra que ela
> recusa o que deve recusar.

## M1b — Wire e autorização cross-language

**Construir:** vetores Rust↔Swift de length framing, CBOR canônico, intent/auth
frames, DATA/CLOSE/REKEY.

**Pronto quando:**
1. CBOR, preimage, digest e frame são **byte-idênticos** nos dois lados;
2. uma assinatura pública fixa verifica nos dois lados;
3. assinatura gerada por cada lado verifica no outro;
4. cada negativa falha (length excessivo, CBOR não canônico,
   assinatura/nonce/epoch/`previous_hash` alterados).

> **Não** exigir que duas assinaturas ECDSA geradas tenham os mesmos bytes.
> Assinaturas ECDSA não são garantidamente byte-idênticas entre implementações —
> nonce e encoding podem variar (algumas stacks usam nonce determinístico, outras
> não). O que precisa ser byte-idêntico é **o que se assina**, não a assinatura.

---

## M1c — CI do core · FECHADO 2026-08-09

**Estado atual:** o #458 (`350203a6`) adicionou aos jobs Linux e macOS as três
invocações explícitas descritas abaixo. O #459 (`d69bc5b1`) adicionou provas
diretas e individualmente não-vácuas dos guards de `identity`, `purpose` e
`revision` do store. Nos logs dos dois runners, não apenas no status dos jobs,
foram observados:

- 206/206 testes do core;
- 0 testes + 13/13 doctests do modelo de controle com a superfície fechada;
- 4/4 testes de CAS multiprocesso e 137/137 invariantes com as features ligadas.

Assim, o bloqueio de evidência que originou este marco está fechado. Isso
**não** promove o `dev_t1_datapath`: satisfaz apenas um dos critérios de
promoção listados acima.

**Achado histórico que originou o marco.** Antes do #458, o núcleo do protocolo
não rodava em CI nenhum. Isso foi verificado por dois caminhos independentes em
2026-08-08:

1. `admin/rust/Cargo.toml` traz `exclude = ["mesh-session-control-model-rs",
   "mesh-session-core-rs"]`, então `cargo test --workspace` nunca os alcança;
2. nenhum workflow e nenhum script **invoca `cargo test`** em qualquer um dos
   dois;
3. eles **não** são desreferenciados: `admin/rust/scripts/graph-gate/run_gate.sh`
   nomeia os dois e entra nos workspaces standalone — mas a fase 4 dele roda
   `cargo check --offline --all-targets`, que **compila** os testes e não executa
   nenhum;
4. dependente com feature ligada compila o crate, mas cargo não roda teste de
   dependência.

Naquela árvore, ~206 testes do protocolo Noise e a CAS multiprocesso do modelo
de controle passavam localmente e **nunca** em automação.

Isso não é dívida de cobertura, é dívida de *evidência*: a decisão de manter o
stack Noise foi tomada porque ele tem essa cobertura. Cobertura que não executa
não sustenta a decisão que ela justificou.

**Implementação adotada:** step explícito em Linux **e** macOS — a CAS do modelo
de controle é construída sobre `std::fs::File::lock`, cujo comportamento é
específico de plataforma. Os testes versionados do M1a/M1b entram no mesmo
gate.

**O modelo de controle exige DUAS invocações, e a primeira sozinha é vácua.** Os
dois integration targets declaram
`required-features = ["test-support", "roster-sync-unratified"]`, então um
`cargo test` simples ali roda 0 unit tests e 0 integration tests — só os 13
doctests:

```
cargo test --locked                                    # superfície fechada (doctests)
cargo test --locked --features test-support,roster-sync-unratified \
  --lib --test model_invariants --test cas_multiprocess   # a suíte de verdade
```

A primeira **não** é redundante e não pode ser substituída pela segunda: o
`src/lib.rs` tem doctests `compile_fail` provando que a superfície gated está
ausente por padrão. Com as features ligadas esses trechos compilam e o doctest
reprova o próprio "não pode compilar" — medido, 5 falhas. Por isso a segunda
seleciona targets explicitamente e não roda doctest.

**Critério verificado:** os dois crates rodam em CI nos dois runners **e** a
não-vacuidade foi medida por comando, não afirmada:

| mutação | comando simples | comando com features |
|---|---|---|
| `replace_exact` → sempre `KnownNoEffect` (CAS que nunca escreve) | rc 0 — **não pega** | rc 101, 4/4 `cas_multiprocess` falham |
| `PROTOCOL_VERSION_BYTE` `0x01`→`0x02` | rc 101 no core, teste de prologue falha | — |

A linha de cima é a razão do marco existir: um CAS que nunca escreve passa no
comando simples. Mutação aplicada e revertida pelo editor, com restauração
provada por blob e a checagem rodando por último — nunca versionada.

### Follow-up: a dupla invocação é convenção, não invariante

Hoje só um comentário no YAML impede que alguém desfaça isso, e o log de CI, que
imprime literalmente `0 tests` para o comando default do modelo de controle, é
uma armadilha nos dois sentidos:

1. alguém lê `0 tests` como defeito e "conserta" ligando as features no primeiro
   comando — reintroduzindo as 5 falhas de `compile_fail`. **Falha ruidosamente**,
   então este caso já se defende sozinho;
2. alguém acha o primeiro comando redundante e o apaga. A suíte gated do segundo
   segue verde, ninguém nota, e a prova de superfície fechada some. **Silencioso.**

**Contar targets/`required-features` no manifesto não fecha o caso 2** — o
manifesto continua perfeito enquanto o YAML perde o comando. O checker precisa
cruzar os dois lados:

- por job (Linux e macOS), parsear o step e exigir, **em ordem**: (1) core
  default; (2) control default **sem** `--features`; (3) control gated com as
  duas features, seleção explícita dos dois targets nomeados e **sem** doctests;
- no manifesto, exigir que `model_invariants` e `cas_multiprocess` mantenham as
  duas `required-features`.

Exigir os targets **nomeados** e as features exatas, nunca um `N` exato: um
terceiro integration target legítimo não deve quebrar o contrato.

Vai em PR próprio, com matriz de mutação do próprio checker: em **cada job
separadamente**, apagar o comando default e trocar a ordem; mover as features
para o comando default; remover um dos dois targets gated; tirar uma
`required-feature`. Assim o teste também prova que não inspeciona só o primeiro
job que encontra. Vive no mecanismo de testes de governança que já existe — sem
acoplar a biblioteca de protocolo ao `.github/`. Não é bloqueador do gate atual;
é hardening contra regressão futura. Especificação de @saira.

> Muda `.github/`, então vai em PR e revisão próprios — não entra de carona num
> branch de feature.

**A promoção do `dev_t1_datapath` exige M1c verde. Esse critério está satisfeito;
os demais continuam obrigatórios.**

## M2 — TUN Linux ↔ utun macOS na LAN · MUDA DE FORMA

**Morreu:** boringtun, `WireGuardDevice`, porta 51820, e qualquer inspeção do tipo
"parece um pacote WireGuard".
**Sobrevive:** TUN/utun, core Rust comum, rota estreita, MTU coerente, fetch HTTP
pela interface virtual, e confidencialidade verificada no underlay.
**Muda:** o transporte é sessão B-SESSAO autenticada + `TunnelFrame::Data`/pump; o
endereço vem do `NetworkSettings`/autoridade, não de um ULA hard-coded (o v1 hoje
é IPv4 escopado).

> **Formato de endereço fica deliberadamente em aberto** — não fixar ULA nem
> família antes da autoridade de endereços fechar. Os invariantes verificáveis já
> valem sem escolher formato: `NetworkSettings` canônico e versionado, rota
> **não-default**, peer distinto do local, e route-scope validado na entrega.

**Pronto quando:**
1. dois nodes estabelecem sessão Noise autenticada na LAN, instalam **somente** a
   rota escopada recebida, e um marcador é buscado pela interface virtual;
2. captura na interface física não contém o marcador nem cabeçalho IP interno legível;
3. bit flip, replay de record, cert/house errado e rota default injetada encerram
   ou negam a sessão;
4. M1a e M1b passam. Sem isso, o fetch entre dois binários nossos não fecha o M2.

> Se o lançamento for relay-first, o M2 continua sendo harness de integração na
> LAN — não promessa de direct path. Direct adaptativo é M12a.

## M3 — Relay content-blind · MUDA DE FORMA

**Morreu:** "um frame = um pacote WireGuard", `type 4`, `SoyehtBind`.
**Sobrevive:** relay outbound-friendly, framing, 443/WSS/TCP conforme a
implementação atual, backpressure, e medição de RSS/CPU/bytes a cada marco.
**Muda:** o relay encaminha records opacos; autenticação e chaves E2E ficam nos
endpoints.

**Pronto quando:**
1. o fetch entre redes distintas funciona só pelo relay;
2. o dump **depois** de qualquer envelope TLS/WSS e **antes** da cifra E2E não
   contém o marcador;
3. o relay não consegue decodificar `TunnelFrame::Data` nem construir sessão
   ativa — e isso é **evidência mecânica**, não afirmação: black-box com relay
   malicioso que tenta decodificar, mais prova de que o processo/artefato do
   relay não recebe segredo de endpoint nem tem API que devolva `TransportState`
   ou plaintext. Se relay e endpoint compartilham binário, a prova é um gate de
   alcançabilidade/dependência ou compile-out, **não** um grep por nome;
4. relay que altera, reordena ou reproduz records causa rejeição; relay que troca
   endpoint/prologue/cert também falha;
5. limites de frame, fila e backpressure exercitados com peer lento, memória limitada.

> O oráculo **não** é "os bytes parecem aleatórios". É marcador ausente + chave
> ausente no relay + tamper/replay fail-closed.

## M4 — iPhone entra · MUDA DE FORMA

**Morreu:** chave WireGuard persistente e core boringtun.
**Sobrevive:** XCFramework Rust dentro da extensão, `NEPacketTunnelProvider`, rota
estreita, sem default route e sem DNS, funcionamento com tela bloqueada, <20 MB.
**Muda:** cada conexão faz uma session-static X25519 nova; a identidade durável é
o **keypair de admissão do device — privada no keystore da plataforma — mais o
cert correspondente** (mesma formulação do M8; o cert sozinho é público e não
autentica). A accessibility do Keychain é definida
pela credencial que a reconexão em background realmente precisa — não copiada da
regra da chave WG. Owner signer com biometria **não** pode ser exigido a cada
reconexão.

**Pronto quando:**
1. em rede móvel, alcança só o recurso autorizado; o resto do tráfego segue normal;
2. lock, restart da extensão e reconexão após o primeiro unlock funcionam sem UI;
   antes do primeiro unlock pós-reboot, falha no estado esperado;
3. cada reconexão prova handshake novo com a **mesma** identidade autorizada;
4. revogação durante tela bloqueada fecha e não reconecta;
5. extensão abaixo de 20 MB em steady state e durante reconnect storm.

## M5 — Control plane, roster e revogação · MUDA DE FORMA

**Morreu:** pubkey WireGuard como identidade, peer table/TOML, N `PeerState`.
**Sobrevive:** autoridade de endereços e rotas, descoberta de endpoints,
`policy_version`/lease, matriz de grants, revogação em <10s.
**Muda:** o control plane distribui estado assinado e verificável (roster, certs,
delegations, grants, expiry, parâmetros de rota); Household/SessionGate decide
DATA por operação. Identidade nunca vem do payload quando já vem do canal/cert.

**Pronto quando:**
1. a matriz de alcance **explicitamente autorizada** funciona entre os 4 devices —
   não assumir "todos veem todos" se a política é por recurso;
2. revogar um device/grant fecha a sessão ativa e faz a nova cerimônia falhar em <10s;
3. as demais relações seguem ativas;
4. adulterar banco/API sem assinatura/epoch/cadeia válida não amplia acesso;
5. control plane indisponível não concede acesso novo; lease expirada falha fechada;
6. teste de carga do mecanismo de versão substitui o polling fixo antes do beta.

## M6 — Egress da VM deny-by-default · SOBREVIVE

Objetivo inalterado: isolar a VM **fora** do guest, antes de compartilhar
qualquer coisa. Root dentro da VM não pode mudar o resultado.

**Morreu:** a exceção nominal `wg0` e qualquer regra que identifique o overlay por
WireGuard — substituir por interface dedicada / mark / VRF do datapath Noise.

**A regra casa por interface/mark, nunca por prefixo — nos dois sentidos.** Não
liberar globalmente um prefixo amplo (`fc00::/7`) *e* não bloqueá-lo globalmente:
o allow amplo fura o isolamento, e o drop amplo mata a própria VPN. O mesmo
endereço tem que passar pela interface de overlay e falhar pela interface normal.

**Construir:** netns + TAP + nftables família **`inet`** (cobre v4 e v6 numa regra
só — um firewall só-v4 passa no teste e vaza por v6); deny de LAN, metadata,
internet e forwarding por default; permitir só vsock/broker e a interface de
overlay autenticada.

**Pronto quando:** o script sai 0 — destinos de laboratório v4 e v6, link-local,
metadata e internet todos falham; broker por vsock funciona; o mesmo pacote passa
pela rota de overlay e falha pela interface normal; `network=internet` alcança a
internet mas continua sem LAN. **Colocar no CI.**

> Implementação e negativas são independentes do datapath e podem começar já. Só o
> positivo "overlay funciona" espera a integração.

## M7 — VM como node · MUDA DE FORMA

**Morreu:** "gera chave WireGuard nova". A session-static Noise já é nova por
conexão e **não** resolve clone — o que precisa ser único é a identidade
persistente da máquina e seu certificado de admissão.

**Construir:** TUN no guest + agente outbound; snapshot dourado sem segredo
definitivo; host injeta `instance_id` + `instance_nonce` únicos por MMDS ou vsock;
nonce diferente força identidade nova **antes** de aceitar qualquer DATA.

> Não dependa de `/dev/vmgenid`: o Firecracker o atualiza para o kernel reseedar o
> PRNG, mas isso não recria estado de userspace. Use como defesa adicional, nunca
> como mecanismo principal. No v1, clonar VM viva preservando identidade é proibido.

**Pronto quando:** o device autorizado alcança a VM pela rota escopada; original e
clone produzem certs/IDs distintos; copiar o disco não deixa o clone reusar o
grant do original; revogar um não derruba o outro; o snapshot inspecionado não tem
chave privada; replay de handshake anterior ao clone falha por nonce/ledger.

## M8 — Passkey, owner signers e recovery · SOBREVIVE

Objetivo inalterado: **login não é autorização de rede.** Trust doc, grants,
membership e recovery formam uma cadeia assinada e anti-rollback.

**Morreu:** exatamente uma linha — "WireGuard device key X25519 no Keychain".
Substituída por três papéis distintos, e a metade secreta importa:

| papel | material | onde |
|---|---|---|
| atos interativos do dono | owner signer P-256 | Secure Enclave, com gesto |
| admissão e reconnect do device | **keypair de admissão do device** — privada no keystore da plataforma — e o cert correspondente | keystore, sem gesto |
| sessão | X25519 Noise fresca por conexão | memória, nunca persistida |

> "Cert de device" sozinho não autentica nada: o cert é público. O que autentica é
> a posse da chave privada correspondente. Reconnect em background usa esse
> keypair, nunca o owner signer.

**Sobrevive integralmente:** WebAuthn, um signer P-256 **por device** (chave do
Secure Enclave é não-extraível por definição — não existe "copiar a House key"),
CBOR canônico com domain separation, `document_version` monotônica,
`previous_hash`, expiry, `revoked_key_ids`, recovery assinada que rotaciona a
trust e revoga os certs antigos.

> O buraco que a v4 já tinha identificado continua fechado aqui: assinar só o
> grant não basta. `group_membership`, adição/remoção de signer, nova versão do
> trust doc e o evento de recovery **também** entram na cadeia — senão o servidor
> amplia o compartilhamento sem tocar no grant.

**Pronto quando:** passkey autentica a conta mas o device novo continua fora da
rede até aprovação; adulterar grant/membership/cert/trust/`previous_hash` sem
reassinar é recusado; rollback para documento válido antigo é recusado; recovery
rotaciona a trust, encerra sessões e exige reaprovação de cada device; a sessão de
background nunca exige biometria a cada reconnect.

## M9 — Capability Broker · SOBREVIVE INTACTO

Zero dependência de datapath. **Pode andar agora.**

Credencial nunca entra na VM, e a VM não escolhe o que chamar. **Não fazer proxy
HTTP genérico** — uma VM comprometida enumera `connection_id`, troca método e URL,
e o broker vira gateway aberto.

**Construir:** app fala HTTP num Unix socket dentro do guest → shim mínimo →
`AF_VSOCK` → broker no host, que resolve a instância **pelo CID atribuído pelo
host**. Nunca confiar num `resource_instance` que veio no JSON. Operações nomeadas
só; valida modelo, tokens, budget, tamanho, ferramentas e rate limit. Orçamento por
instância, não por usuário.

**Pronto quando:** um canary sintético conhecido (não uma credencial real) não
aparece em FS, env nem argv dentro da VM — essa é a prova forte —, complementado
por uma **denylist de nomes/prefixos de credencial conhecidos**, não por substring
genérica: `grep -i key` casa com variável legítima e ensina a equipe a ignorar o
resultado. Operação declarada funciona; não declarada dá 403;
`resource_instance` forjado é ignorado em favor do CID; budget corta e audita; e
reinício/clonagem não herda orçamento indevido.

> O teste prova **ausência de credencial**, não ausência de ambiente — `env` sempre
> terá `PATH`. Exigir env vazio seria um critério impossível que ninguém cumpre e
> todo mundo acaba ignorando.

## M10 — Agente de memorização · CORE SOBREVIVE

Primeiro workload: zero credencial, `network: broker-only`, zero regulação.
Exercita a stack inteira sem risco.

**Morreu:** nada de WireGuard. Só o endereço ULA fixo vira endpoint/rota escopada
entregue pelo datapath.

Dois estados de pronto, separados de propósito — o core não pode ficar refém do
datapath, e o E2E não pode ser declarado sem ele:

**M10-core pronto quando:** upload de um arquivo de teste **sem dados pessoais**;
perguntas e agendamento persistem por 3 dias e sobrevivem a restart; dentro da VM
internet e LAN falham e o broker permitido funciona; nenhum segredo em FS ou env.
Nada disso precisa de datapath.

**M10-E2E pronto quando:** um device autorizado alcança a UI pela rota escopada, e
revogar o acesso corta o tráfego novo **sem apagar os dados do agente**. Isso
espera M7.

## M11 — Compartilhar VM (host Linux) · INVARIANTES SOBREVIVEM

**Morreu:** peer/config WG, ULA fixo, e revogação por remoção de peer.
**Muda:** oferta/intenção B-SESSAO vinculada a audience/device/resource/expiry;
SessionGate por operação; ACL exata device↔VM.

**Construir:** convite de uso único com TTL curto → aceite → grant assinado e
encadeado. Firewall stateful: convidado→VM abre conexão; VM→convidado só
`ESTABLISHED`/`RELATED`. Continua **Linux-only** enquanto o macOS não tiver
filtragem host-side equivalente (as VMs macOS usam NAT do Virtualization
Framework); hosts macOS entram como devices pessoais normalmente.

> "Zero linha de datapath nova" só vale **depois** que M2–M7 promoverem um datapath
> existente. O M11 não pode virar atalho para abrir o gate.

**O convidado de teste tem trust root / Household DISTINTO.** Um "convidado" que é
outro device da mesma casa não prova fronteira externa nenhuma — prova só a ACL
interna. Pode ser fixture ou simulador neutro; não precisa de pessoa real nem de
dado de pessoa real.

**Pronto quando** o convidado autorizado recebe rota só da VM **e** falham, no
sentido seguro: alcançar o host, outros devices ou outra VM; a VM iniciar conexão
para o convidado ou para a LAN dele; grant adulterado/expirado/reusado; e o relay
ampliar audience sem invalidar a assinatura. Revogação em <10s, com os demais
devices intactos. **Se algum desses passar, pare tudo e conserte.**

## M12a — Direct path v1 · MUDA SUBSTANCIALMENTE

**Morreu:** `SoyehtBind`, "STUN no mesmo socket WireGuard", dispatch por
receiver-index, e a continuidade da mesma sessão criptográfica entre caminhos.

**Decisão para não inventar um segundo datapath:** o direct v1 é um **stream
confiável novo** (LAN e IPv6 primeiro), com **cerimônia Noise completa nova**. O
relay continua sendo outro carrier. Não migrar `TransportState` entre sockets e não
introduzir datagrama/QUIC implicitamente. Hole punching por UDP vira marco futuro
separado, se os dados do M0a mostrarem necessidade.

**Escopo, e a fronteira com o M12b:** o M12a escolhe o carrier **ao abrir uma
sessão nova**. Perder o caminho e trocar de rede **no meio de uma sessão viva** é
M12b. Sem essa linha, "cada troca de caminho" abrange os dois e nenhum dos dois
fica testável.

**Construir:**
- fonte de candidatos LAN/IPv6 publicada pelo control plane, com TTL;
- `PathProvider`/connector abstrato que entrega um stream ordenado, seja relay ou
  direct — o pump não sabe qual;
- probe autenticado do candidato (candidato não autenticado nunca vira caminho);
- seleção direct-first com fallback para relay;
- cerimônia Noise completa nova a cada carrier, revalidando cert/intent/grant/expiry
  antes de trocar o pump;
- métricas de latência, CPU e `bytes_relayed`.

**Pronto quando:** em LAN/IPv6 alcançável o caminho é direto e `bytes_relayed`
fica em zero durante tráfego real; bloquear o direct cai para relay de forma
transparente; candidato falso ou peer errado falha sem causar downgrade para uma
sessão menos autorizada; direct e relay entregam a **mesma** rota e audience; e
**cada sessão aberta num carrier diferente** mostra handshake novo e recusa
records antigos — redação deliberada, para não reintroduzir migração ao vivo, que
é M12b.

> Se o produto exigir direct através de NAT IPv4 em rede móvel, isso **não** cabe
> silenciosamente aqui: é decisão explícita de carrier datagrama e conformance nova.

## M12b — Mobilidade wifi ↔ rede móvel · MUDA SUBSTANCIALMENTE

Separado de propósito: sobreviver a troca de rede é bem mais difícil que
estabelecer direct, e não deve segurar o M12a.

**Morreu:** "rebind do mesmo socket WG" e "a mesma sessão criptográfica
sobrevive". **O objetivo é a aplicação sobreviver, não a sessão.**

**Construir:** supervisor que detecta a mudança, mantém a interface virtual e a
rota enquanto redescobre carrier, encerra a sessão antiga, abre stream novo com
handshake e auth novos, e reconecta o pump. Fila transitória estritamente
limitada — no overflow, **dropar** (o TCP interno retransmite), nunca crescer sem
limite.

**M12b-0 — congelar o SLO, antes de implementar.** Medir a baseline de pausa e de
memória em cenários definidos, aprovar e congelar o número. Inventar um SLO sem
baseline seria pior que não ter: vira um número que ninguém consegue defender e
que o primeiro teste vermelho renegocia.

**Pronto quando:** um download iniciado no wifi termina byte-idêntico depois de
cortar o wifi, sem gesto do usuário; vale nos dois sentidos (direct↔relay); a
pausa máxima e a memória em reconnect storm ficam **dentro do SLO congelado no
M12b-0**; revogar durante a janela de troca impede a sessão nova; replay de
records da sessão velha falha; e sem carrier o estado fica degradado, sem instalar
default route nem vazar pela rede física.

---

## Regras

**Não avance com teste falhando.** Especialmente M6 e M11 — são os que expõem a
rede de casa.

**Não construa antes da hora:** exit node · subnet router · desktop remoto · QUIC ·
peer relay entre casas · kernel WireGuard · iniciação de pagamento (licença do
BCB) · mDNS/broadcast (não funciona em rota escopada — declare como não-objetivo).

**Logs desde o M3:** separar operacional de legal · IDs pseudônimos · retenção por
região, configurável · legal hold · deleção/anonimização por conta desde o início.

**Núcleo sem país:** IDs sem significado regional, sem CPF, sem telefone
brasileiro, billing em USD. Regra de país fica na borda.

**Meça o relay em cada marco:** RSS, CPU, bytes.

**Nunca comprometa dado real em teste ou documento:** nem IP público, nem hostname
pessoal, nem nome de máquina. Use `192.0.2.x` / `203.0.113.x` / `2001:db8::/32` e
aliases neutros.

---

## Proveniência

Revisão conjunta 2026-08-08. Auditoria do stack existente e decisão do datapath:
`@gloria`. Releitura marco a marco de M2–M12b, substituições concretas e ordem/DAG:
`@saira`. Contexto de iOS/NetworkExtension e as duas amostras de campo do M0a:
`@gianna`. A v4 original é do Caio e continua sendo a fonte dos objetivos de
produto — o que mudou é a arquitetura por baixo deles, não o que o produto promete.
