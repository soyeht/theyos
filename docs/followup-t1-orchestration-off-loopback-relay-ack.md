# Follow-up: off-loopback relay in the T1 orchestration script

**Severity:** LOW. The primary **loopback** dev-host T1 run
(`127.0.0.1:49152`) is fully covered and unaffected. This defers the
off-loopback (e.g. Tailscale-transport checkpoint) variant until the driver
exposes and gates the runner's second acknowledgement.

## Symptom

`scripts/run-t1-dev-datapath.sh` has no `--allow-public-relay-ack` flag in its
usage/parse, and its final `run-device-datapath` invocation omits it. So:

- For a non-loopback `--relay-endpoint`, the device runner's own gate requires
  the public-relay ack and will refuse the datapath — the script cannot complete
  the off-loopback variant it appears to allow.
- Worse for boundary/fail-closed: the script can start the loopback relay bin
  and the claw responder **before** the runner fails on the missing second ack
  (launch-before-fail), rather than refusing up front.

## What works vs. fails

- **Works:** the loopback flow (`--relay-endpoint 127.0.0.1:49152`, the default)
  end to end.
- **Fails / gap:** any non-loopback `--relay-endpoint` — no flag to pass the
  second ack, and no pre-launch fail-closed check.

## Fix (do this before documenting an off-loopback run in the runbook)

1. Add `--allow-public-relay-ack <ack>` to the script usage/`parse_args`.
2. Thread it through to the claw responder (`--allow-public-relay-ack`) and the
   device runner (`--allow-public-relay-ack`) invocations.
3. Fail closed **before any launch**: when `--relay-endpoint` is non-loopback,
   require the public-relay ack (exact string
   `dev-host public relay dial allowed; no production activation`); otherwise die
   before starting the relay/claw. Add a test in
   `scripts/test_run_t1_dev_datapath.sh` for the non-loopback pre-launch
   rejection and for the accepted off-loopback path with the ack.

Then re-add the off-loopback checkpoint to
`product-a-per-claw-vpn-t1-phase2-3-run-runbook.md` (currently loopback-only).

## Files of interest

- `scripts/run-t1-dev-datapath.sh` (usage/parse, final runner call, prod_guard)
- `admin/rust/t1-iptunnel-dev-runner-rs/src/main.rs` — the runner's public-relay
  gate (`RunDeviceDatapath { allow_public_relay_ack }` +
  `validate_loopback_relay_endpoint_or_ack`)
- `docs/product-a-per-claw-vpn-t1-phase2-3-run-runbook.md` — Step 3 (loopback-only)
