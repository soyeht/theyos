# macOS Runner Recovery Runbook

Operator-facing guide for diagnosing and recovering from a failed macOS
guest-image preparation (the `init-macos-guest` / base-image build path).

How a failure surfaces: `GET /bootstrap/status` returns `guest_image_status`
(`failed`), `guest_image_phase`, a machine-readable `guest_image_failure_code`,
and `guest_image_error` (display-only detail). Key recovery off the code, not
the free-text error. The code is the stable contract; the codes and scopes
below are owned by `core-rs/src/guest_image_failure.rs`.

## Recovery scope (failure_scope)

Each failure code carries a recovery scope that says whether and how it clears:

- `current_boot`: tied to the boot it happened on; a host reboot clears it and
  the status reader stops blocking on the next boot.
- `retryable`: transient; retry directly, no reboot or reinstall needed.
- `persistent`: needs an environment fix or a reinstall; a reboot does not help.
- `unknown`: unrecognized/future scope; treated conservatively as persistent
  (keep blocking) so an older reader never silently un-blocks.

## Failure codes and operator actions

| failure_code                | scope        | meaning                                                                  | operator action                                                      |
|-----------------------------|--------------|--------------------------------------------------------------------------|----------------------------------------------------------------------|
| host_vm_limit_reached       | current_boot | host hit Apple's concurrent macOS-VM limit (often a leaked/orphan session)| reboot the host to clear the active-VM count, then retry; no reinstall|
| insufficient_disk           | retryable    | not enough free space to build the guest image                           | free disk space, then retry                                          |
| ipsw_download_failed        | retryable    | the macOS restore image download failed                                  | retry (transient network); check connectivity                       |
| ipsw_incompatible           | persistent   | the restore image is not compatible with this host                       | reprepare with a compatible restore image                           |
| entitlement_missing         | persistent   | the virtualization entitlement is missing or not honored                 | fix code-signing/entitlements, reinstall the runner, then retry      |
| helper_missing              | persistent   | a required helper binary was missing                                     | reinstall the runner so the helper binary is present                 |
| virtualization_unavailable  | persistent   | this host/OS cannot run VMs (isSupported was false)                       | use a supported host; a reboot or plain retry will not help          |
| unknown                     | persistent   | unclassified/future failure                                              | inspect guest_image_error; keep blocking until the cause is understood|

## Orphan / leaked VZ sessions

An orphaned active-VM session (a VZ session whose owner process died) still
counts against the host limit and surfaces as `host_vm_limit_reached` with
scope `current_boot`. A host reboot releases the leaked session; on the next
boot the status reader no longer blocks. No reinstall is required.

## Not yet coded (per-instance failures)

These are surfaced today as a generic instance failure (instance status
`failed` with a human-readable error) and do NOT yet carry a sanitized
`failure_code`: provisioning timeout, snapshot save/load failures, and generic
per-instance download errors. Diagnose them from the instance error text until
per-instance codes are added (tracked separately).

## Rules

- Never paste real local paths, hostnames, or IP addresses into reports or
  tickets; cite the `failure_code` and the `guest_image_phase` instead.
- `guest_image_error` is display-only detail; `guest_image_failure_code` is the
  stable key. Localized client copy is keyed off the code.

Out of scope here: artifact signing, the engine software-keys flag, TLS,
checksums, the Swift client, and Product A / nvpn.
