# theyOS LLM proxy — NixOS systemd module.
#
# Imported by nix/module.nix. When `services.theyos.enable = true` and the
# parent module sets `services.theyos.llm-proxy.enable` (default `true`),
# this declares a systemd unit that runs `theyos-llm-proxy` as the primary
# theyOS user (`services.theyos.user`) so:
#
# 1. Credentials persist in the file keystore at `$HOME/.theyos/keystore/`
#    (survives reboot — kernel keyring did not).
# 2. CLI-OAuth providers (claude-cli, codex, gemini-cli) inherit a real
#    `$HOME` with their interactive login state.
# 3. Profile files at `$HOME/.theyos/llm-profiles/` are the same ones the
#    user edits manually or that the admin API writes — single source of
#    truth, no service-account split.
#
# Multi-tenant deployment ([[multi-tenant-deployment]]) — where each
# user gets their own proxy instance — is v1.x and out of scope here.

{ config, lib, pkgs, ... }:

let
  theyosCfg = config.services.theyos;
  cfg = theyosCfg.llm-proxy;
  userHome = "/home/${theyosCfg.user}";

  # Resolve the primary user's group dynamically. On NixOS, `isNormalUser`
  # creates a per-user group named after the user (not `users`). Hard-
  # coding `Group = "users"` would mismatch the actual group on hosts
  # that follow the default, leaving the service running with the wrong
  # group identity and the tmpfiles chowns failing silently.
  userGroup = config.users.users.${theyosCfg.user}.group;

  # CLI-OAuth providers write session/token state during normal
  # operation (`claude` refreshes its token; `codex` caches
  # conversation history; `gemini` and `opencode` similar). v1.1 will
  # re-pin ProtectHome and BindPaths these dirs back in. See the
  # serviceConfig comment for the deferred-hardening rationale.
in
{
  options.services.theyos.llm-proxy = {
    enable = lib.mkEnableOption "theyOS host-side LLM proxy daemon" // {
      default = theyosCfg.enable;
    };

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        Package providing the `bin/theyos-llm-proxy` binary. Defaults to
        the same `services.theyos.package` as the rest of the platform —
        every theyOS artifact ships from one runtime build.
      '';
      default = theyosCfg.package;
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 18900;
      description = ''
        Loopback port the proxy listens on. Claws reach the proxy via
        reverse SSH tunnel that maps guest 127.0.0.1:<port> to host
        127.0.0.1:<port>. Default matches
        `core_rs::claw_llm::DEFAULT_LLM_PROXY_PORT`.
      '';
    };

    profileDir = lib.mkOption {
      type = lib.types.path;
      default = "${userHome}/.theyos/llm-profiles";
      description = ''
        Directory holding TOML profile files (`default.toml` and per-claw
        overrides). Owned by `services.theyos.user`; the admin HTTP API
        writes into this directory.
      '';
    };

    keystoreDir = lib.mkOption {
      type = lib.types.path;
      default = "${userHome}/.theyos/keystore";
      description = ''
        Root of the on-disk credential store. Used when
        `THEYOS_LLM_KEYSTORE=file` (the production default). Files are
        written 0600 with atomic rename — see `keystore_rs::FileKeystore`.
      '';
    };

    auditLog = lib.mkOption {
      type = lib.types.path;
      default = "${userHome}/.theyos/.run/llm-audit.log";
      description = ''
        JSONL audit log path. Append-only; one record per chat request
        with provider, claw_type, model, latency, status (no prompts or
        credentials). Empty string disables audit logging.
      '';
    };

    keystoreKind = lib.mkOption {
      type = lib.types.enum [ "auto" "file" "system" "tpm" ];
      default = "auto";
      description = ''
        Credential backend:
        - `auto` (default): pick the best available — TPM2-sealed via
          `systemd-creds` when a TPM is present, plain `0600` file
          otherwise. This is the recommended setting for production.
        - `tpm`: explicit TPM2 sealing via `systemd-creds`. Fails fast
          at startup if no TPM is reachable. Pick this on hardened
          hosts where falling back to plaintext at rest is unacceptable.
        - `file`: 0600 files under [`keystoreDir`]. No encryption at
          rest beyond filesystem ACLs. Use for hosts without a TPM
          where Secret Service is also unavailable.
        - `system`: OS keystore (Linux Secret Service / kernel keyring).
          Kernel keyring is wiped on service restart — use only when a
          Secret Service daemon is reachable from the unit.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info,llm_proxy=info,tower_http=warn";
      description = "RUST_LOG filter for the proxy daemon.";
    };
  };

  config = lib.mkIf cfg.enable {
    # Enable TPM2 user-mode access so the proxy daemon can seal and
    # unseal credentials via systemd-creds without root. The default
    # `/dev/tpmrm0` permission on NixOS is `0600 root:root` which
    # gives even legitimate services no path to the chip; flipping
    # `security.tpm2.enable` installs the udev rules + tss group so
    # the device becomes `0660 tss:tss` and members of `tss` can
    # transact with it.
    #
    # The `tssGroup` option pins the resolved group name in case a
    # future NixOS release changes the default.
    security.tpm2 = {
      enable = lib.mkDefault true;
      tssGroup = lib.mkDefault "tss";
    };

    # Add the proxy's service user to the `tss` group so the daemon
    # inherits TPM access at start-up. Adding to `extraGroups` via
    # `mkAfter` is non-destructive — it merges with whatever groups
    # the user is already in for other reasons.
    users.users.${theyosCfg.user}.extraGroups = lib.mkAfter [ "tss" ];

    # systemd's `io.systemd.credentials.{encrypt,decrypt}` polkit
    # actions default to `auth_admin_keep` — meaning every encrypt /
    # decrypt prompts for admin authentication. That's the right
    # default for interactive CLI use, but it breaks an unattended
    # service: the proxy can't pop a prompt and there's no admin
    # session to consult. The rule below carves out a narrow grant
    # for the proxy's service user, so its `systemd-creds` invocations
    # complete non-interactively.
    #
    # Scope: only this user, only these two actions, no wildcard. The
    # blast radius if this user is compromised is the same as it was
    # before (the proxy already owns the keystore), so we're not
    # expanding privilege — we're matching what the threat model
    # already assumes.
    security.polkit.extraConfig = ''
      polkit.addRule(function(action, subject) {
        if ((action.id == "io.systemd.credentials.encrypt" ||
             action.id == "io.systemd.credentials.decrypt") &&
            subject.user == "${theyosCfg.user}") {
          return polkit.Result.YES;
        }
      });
    '';

    systemd.tmpfiles.rules = [
      # Bootstrap the directories the proxy expects before first launch.
      # Mode 0700 — only the owning user can read credentials or audit
      # records. Group is the user's primary group (not "users") so the
      # entries don't fail on hosts that follow NixOS's `isNormalUser`
      # default of per-user groups.
      "d ${userHome}/.theyos                 0700 ${theyosCfg.user} ${userGroup} -"
      "d ${userHome}/.theyos/.run            0700 ${theyosCfg.user} ${userGroup} -"
      "d ${cfg.profileDir}                   0700 ${theyosCfg.user} ${userGroup} -"
      "d ${cfg.keystoreDir}                  0700 ${theyosCfg.user} ${userGroup} -"
    ];

    systemd.services.theyos-llm-proxy = {
      description = "theyOS LLM proxy (host-side provider multiplexer)";
      documentation = [ "https://theyos.dev/docs/llm-proxy" ];
      wantedBy = [ "multi-user.target" ];
      # `systemd-tmpfiles-setup.service` creates the dirs listed in
      # `systemd.tmpfiles.rules` above. Without this ordering the unit
      # has been observed to race tmpfiles on first boot: it starts
      # against a missing profile dir, writes a first-run stub that
      # silently fails, and exits 0 (the `NoProvider` branch). The
      # `requires` line escalates that to a hard ordering so a tmpfiles
      # failure also fails the proxy unit instead of masking it.
      requires = [ "systemd-tmpfiles-setup.service" ];
      after = [
        "network.target"
        "systemd-tmpfiles-setup.service"
        "local-fs.target"
      ];

      environment = {
        THEYOS_LLM_PROXY_PORT     = toString cfg.port;
        THEYOS_LLM_PROXY_BIND     = "127.0.0.1";
        THEYOS_LLM_PROFILE_DIR    = cfg.profileDir;
        THEYOS_LLM_AUDIT_LOG      = cfg.auditLog;
        THEYOS_LLM_KEYSTORE       = cfg.keystoreKind;
        THEYOS_LLM_KEYSTORE_DIR   = cfg.keystoreDir;
        HOME                      = userHome;
        # Some CLI providers (claude, codex, gemini) read XDG dirs for
        # their OAuth state; pin both to the same user home so subprocess
        # auth resolution is deterministic regardless of distro defaults.
        XDG_CONFIG_HOME           = "${userHome}/.config";
        XDG_DATA_HOME             = "${userHome}/.local/share";
        XDG_CACHE_HOME            = "${userHome}/.cache";
        RUST_LOG                  = cfg.logLevel;
      };

      # Put the CLI-OAuth binaries the proxy may spawn on PATH. They
      # follow OAuth out-of-band (interactive `claude /login`,
      # `codex login`, etc.); the proxy just exec()s them with
      # stdin → stdout streaming. Keep this list in sync with the
      # CliOauth provider entries in
      # `admin/rust/llm-proxy-rs/src/catalog/providers.rs` so every
      # catalog entry has a binary the daemon can actually find.
      #
      # `systemd` is here for `systemd-creds` — the TPM2 keystore
      # backend shells out to it for seal/unseal. NixOS systemd units
      # don't automatically inherit /run/current-system/sw/bin, so an
      # explicit entry keeps `THEYOS_LLM_KEYSTORE=auto` working
      # without an operator having to remember to extend PATH.
      path = with pkgs; [
        coreutils
        systemd
        claude-code
        codex
        opencode
      ];

      # Defensive `install -d` before the daemon starts. tmpfiles SHOULD
      # have created these already (see the `requires` above) but tmpfiles
      # is best-effort on some filesystems and home-dir layouts; the
      # `+` prefix runs as root, idempotently. Without this, the first
      # boot after a `nixos-rebuild switch` has been observed to leave
      # the dirs missing and the daemon's "no profile found" branch
      # runs against nothing.
      preStart = ''
        ${pkgs.coreutils}/bin/install -d -o ${theyosCfg.user} -g ${userGroup} -m 0700 \
          ${userHome}/.theyos \
          ${userHome}/.theyos/.run \
          ${cfg.profileDir} \
          ${cfg.keystoreDir}
      '';

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/theyos-llm-proxy";
        Restart = "on-failure";
        RestartSec = "5s";

        User = theyosCfg.user;
        Group = userGroup;

        # systemd does not pull supplementary groups from /etc/group at
        # service start — only the ones listed here are granted. The
        # proxy needs `tss` to reach /dev/tpmrm0 (0660 root:tss) for
        # TPM-sealed credential decrypt. Adding the user to `tss` via
        # `users.users.${u}.extraGroups` (above) makes the user a member
        # of the group; this line is what actually gives the running
        # unit that group at exec time.
        SupplementaryGroups = [ "tss" ];

        # `preStart` runs as root for the directory chowns; the main
        # process drops to the resolved User/Group.
        PermissionsStartOnly = true;

        # Hardening — the proxy needs network out, its profile/keystore
        # dirs (inside $HOME/.theyos), and access to a handful of CLI-
        # OAuth state dirs that subprocesses (claude, codex, gemini,
        # opencode) refresh during normal operation.
        #
        # KNOWN GAP (v1.1 followup): `ProtectHome` and `ReadWritePaths`
        # are disabled here because systemd sets up the unit's mount
        # namespace BEFORE ExecStartPre runs, and the bind sources
        # ($HOME/.theyos and friends) don't yet exist on a fresh
        # install. Hosts where `systemd-tmpfiles-setup.service` is
        # broken (we observed this on devs — exit 73 in 2008, never re-
        # ran across reboots) leave the dirs missing forever, and our
        # unit then loops in "Failed to set up mount namespacing".
        #
        # Three real fixes, deferred to v1.1:
        #   1. Move state to /var/lib/theyos-llm + use StateDirectory=
        #      (systemd creates that pre-namespace).
        #   2. Separate `theyos-llm-proxy-prepare.service` (root,
        #      ProtectHome=false) that just creates the dirs, sequenced
        #      via Requires=/Before=.
        #   3. TemporaryFileSystem=/home with explicit BindPaths for
        #      every subdir we need pre-populated.
        #
        # For v1, ship without ProtectHome. The other hardening still
        # applies: NoNewPrivileges, restricted syscalls, locked-down
        # namespaces, read-only system paths. Worst-case blast radius
        # of a compromised proxy is approximately equal to a compromise
        # of `cfg.user` directly (the proxy runs as that user) —
        # documented in the v1 threat model.
        ProtectSystem = "strict";
        # ProtectHome intentionally omitted — see comment above.
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectClock = true;
        NoNewPrivileges = true;
        LockPersonality = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];

        # ReadWritePaths / BindPaths intentionally omitted — see
        # ProtectHome comment above. Without ProtectHome, the unit
        # inherits the user's full home read-write, so these directives
        # would be no-ops anyway. v1.1 followup re-enables them along
        # with one of the namespace-prep approaches.

        StandardOutput = "journal";
        StandardError = "journal";
      };
    };
  };
}
