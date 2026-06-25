# Product A Group Operation Fixtures

Canonical-CBOR fixtures for the Plane-1 Group/Public relay membership API. These
fixtures are byte-level drift guards for Swift/Rust decoders.

## GroupOpRequest

`GroupOpRequest` is `{ v: u8, op: GroupOp }`; `GroupOp` is externally tagged
with snake_case variant names. Maps use canonical CBOR ordering.

Canonical inputs:

- `group_id`: `group_alpha`
- create `name`: `Alpha Group`
- add_member `member_id`: `g_leqzmohi5sc7vetm3aajdt2tppasgg5oquvfjs6lxsfp4ljhj6pq`
- add_member `label`: `phone_alpha`
- grant_claw `claw_id`: `claw_alpha`

create:

```text
a2617601626f70a166637265617465a2646e616d656b416c7068612047726f75706867726f75705f69646b67726f75705f616c706861
```

add_member:

```text
a2617601626f70a16a6164645f6d656d626572a3656c6162656c6b70686f6e655f616c7068616867726f75705f69646b67726f75705f616c706861696d656d6265725f69647836675f6c65717a6d6f6869357363377665746d3361616a64743274707061736767356f717576666a73366c78736670346c6a686a367071
```

grant_claw:

```text
a2617601626f70a16a6772616e745f636c6177a267636c61775f69646a636c61775f616c7068616867726f75705f69646b67726f75705f616c706861
```

## GroupsListResponse

`GET /api/v1/claw-share/groups` returns owner-display state as canonical CBOR:

`{ v:1, groups:[{ name, members:[{ label, member_id, device_count }], group_id, granted_claws:[claw_id] }], published_claws:[claw_id] }`

Canonical inputs:

- group: `group_id` = `group_alpha`, `name` = `Alpha Group`
- member: `member_id` = `g_member_alpha`, `label` = `Alice's phone`, `device_count` = `1`
- `granted_claws` = `[claw_alpha]`
- `published_claws` = `[]`

```text
a36176016667726f75707381a4646e616d656b416c7068612047726f7570676d656d6265727381a3656c6162656c6d416c69636527732070686f6e65696d656d6265725f69646e675f6d656d6265725f616c7068616c6465766963655f636f756e74016867726f75705f69646b67726f75705f616c7068616d6772616e7465645f636c617773816a636c61775f616c7068616f7075626c69736865645f636c61777380
```
