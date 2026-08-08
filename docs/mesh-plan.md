# Soyeht — plano de construção do mesh

**v5 — executável.** Substitui a v4 congelada (`soyeht-plano.md`), que pressupunha
um datapath WireGuard que não existe e não vai ser construído.

**Hardware:** `linux` (sempre ligado, host das VMs) · `macstudio` · `macbook` · `iphone`

---

## A decisão que gerou esta versão

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

```
Lane A (independência)   M1a conformance Noise ─┐
                         M1b wire/auth RS↔Swift ─┤
                                                 ├─→ M2 TUN↔utun ─→ M3 relay ─→ M4 mobile
Lane B (sem datapath)    M6 · M8 · M9 · M10-core ┘                    │
                                                                      ├─→ M5 control plane
                                                                      ├─→ M7 VM como node
                                                                      ├─→ M11 compartilhar
                                                                      └─→ M12a direct ─→ M12b mobilidade
```

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
| macstudio / ethernet | ✅ |
| iphone / wifi | ✅ |
| iphone / 5G | ❌ aparelho sem dado celular (linha/plano) |
| linux / ethernet | ❌ host `devs` inalcançável |
| macbook / wifi casa · wifi café | ❌ precisa de acesso físico |

Duas lições que ficaram no código:

- **21 testes offline passaram enquanto zero pacotes saíam da máquina.** Socket
  v4 + `to_socket_addrs()` devolvendo o AAAA primeiro = `EINVAL` em todo envio.
  Nenhum teste alcançava a escolha do destino, o único passo sem entrada nossa.
- **Toda linha grava `tunnel_interfaces`.** Duas amostras de campo foram tiradas
  com uma VPN de produção conectada e ninguém checou. A validade delas teve que
  ser provada depois, comparando o IP público observado com o de outro host atrás
  do mesmo NAT. Agora a linha se autodescreve.

---

## M1a — Conformance Noise independente

**Construir:** exportador de vetores congelados do handshake e dos primeiros
records; verificador numa segunda implementação Noise, em outra linguagem, sem
compartilhar crypto/estado com o `snow`.

**Pronto quando:** a segunda implementação reproduz transcript hash e records
byte-a-byte, e as negativas (bit flip, replay, reorder, prologue trocado) falham.

## M1b — Wire e autorização cross-language

**Construir:** vetores Rust↔Swift de length framing, CBOR canônico, intent/auth
frames, DATA/CLOSE/REKEY.

**Pronto quando:** os dois lados concordam byte-a-byte nos positivos **e** recusam
cada negativa (length excessivo, CBOR não canônico, assinatura/nonce/epoch/
`previous_hash` alterados).

---

## M2 — TUN Linux ↔ utun macOS na LAN · MUDA DE FORMA

**Morreu:** boringtun, `WireGuardDevice`, porta 51820, e qualquer inspeção do tipo
"parece um pacote WireGuard".
**Sobrevive:** TUN/utun, core Rust comum, rota estreita, MTU coerente, fetch HTTP
pela interface virtual, e confidencialidade verificada no underlay.
**Muda:** o transporte é sessão B-SESSAO autenticada + `TunnelFrame::Data`/pump; o
endereço vem do `NetworkSettings`/autoridade, não de um ULA hard-coded (o v1 hoje
é IPv4 escopado).

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
3. o relay só observa metadado inevitável (tamanho, timing, routing token) — não
   decodifica `TunnelFrame::Data` nem constrói sessão ativa;
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
o cert de device admitido pelo Household. A accessibility do Keychain é definida
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
Continua proibido liberar `fc00::/7` ou prefixo amplo: a regra é **por interface**,
não por prefixo, senão um `drop` global mata a própria VPN.

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
Substituída por: owner signer P-256 para atos interativos; cert de device para
admissão e reconnect; X25519 de sessão Noise fresca, nunca persistida como
identidade.

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

**Pronto quando:** `grep -rn "sk-"` e `env` vazios dentro da VM; operação declarada
funciona; não declarada dá 403; `resource_instance` forjado é ignorado em favor do
CID; budget corta e audita; e reinício/clonagem não herda orçamento indevido.

## M10 — Agente de memorização · CORE SOBREVIVE

Primeiro workload: zero credencial, `network: broker-only`, zero regulação.
Exercita a stack inteira sem risco.

**Morreu:** nada de WireGuard. Só o endereço ULA fixo vira endpoint/rota escopada
entregue pelo datapath.

**Pronto quando:** upload de um arquivo de teste **sem dados pessoais**; perguntas
e agendamento persistem por 3 dias e sobrevivem a restart; dentro da VM,
internet e LAN falham e o broker funciona; nenhum segredo em FS ou env; revogar
acesso impede tráfego novo à UI sem apagar os dados do agente.

> Core, broker e isolamento fecham sem datapath. Só o "device remoto acessa a UI"
> espera M7 — então não chame o M10 inteiro de pronto antes desse E2E.

## M11 — Compartilhar VM (host Linux) · INVARIANTES SOBREVIVEM

**Morreu:** peer/config WG, ULA fixo, e revogação por remoção de peer.
**Muda:** oferta/intenção B-SESSAO vinculada a audience/device/resource/expiry;
SessionGate por operação; ACL exata device↔VM.

**Construir:** convite de uso único com TTL curto → aceite → grant assinado e
encadeado. Firewall stateful: convidado→VM abre conexão; VM→convidado só
`ESTABLISHED`/`RELATED`. Continua **Linux-only** enquanto o macOS não tiver
filtragem host-side equivalente (as VMs macOS usam NAT do Virtualization
Framework); MacBook e Mac Studio entram como devices pessoais normalmente.

> "Zero linha de datapath nova" só vale **depois** que M2–M7 promoverem um datapath
> existente. O M11 não pode virar atalho para abrir o gate.

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

**Pronto quando:** em LAN/IPv6 alcançável o caminho é direto e `bytes_relayed`
fica em zero durante tráfego real; bloquear o direct cai para relay de forma
transparente; candidato falso ou peer errado falha sem causar downgrade para uma
sessão menos autorizada; direct e relay entregam a **mesma** rota e audience; cada
troca mostra handshake novo e recusa records antigos.

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

**Pronto quando:** um download iniciado no wifi termina byte-idêntico depois de
cortar o wifi, sem gesto do usuário; vale nos dois sentidos (direct↔relay); a
pausa máxima e a memória em reconnect storm ficam dentro de um SLO definido
**antes** de marcar pronto; revogar durante a janela de troca impede a sessão
nova; replay de records da sessão velha falha; e sem carrier o estado fica
degradado, sem instalar default route nem vazar pela rede física.

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
