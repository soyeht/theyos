# Rust workspace build using crane.
# Can produce either the runtime subset or the full builder workspace,
# depending on `excludedMembers`.
{ pkgs, craneLib, packageName ? "theyos-admin", excludedMembers ? [ "vmrunner-macos-rs" ] }:

let
  flakeLockSha256 = builtins.hashFile "sha256" ../../flake.lock;
  # Use crane's cleanCargoSource plus extra filters for non-Rust assets that
  # crates pull in via include_str!:
  #   - .html files (e.g. server-rs/.../privacy.html)
  #   - .sh files (e.g. core-rs/src/claw_llm_bootstrap.sh)
  #   - .json files (test fixtures, contract docs)
  #   - anything under an `assets/` directory (e.g.
  #     rootfsbuilder-rs/assets/how-to-publish.md)
  src = pkgs.lib.cleanSourceWith {
    src = ../../admin/rust;
    filter = path: type:
      (craneLib.filterCargoSources path type)
      || (builtins.match ".*\\.html$" path != null)
      || (builtins.match ".*\\.sh$" path != null)
      || (builtins.match ".*\\.json$" path != null)
      || (builtins.match ".*/assets/.*" path != null);
  };

  # Contract test fixtures live at admin/contracts/ (sibling of admin/rust/).
  # Tests resolve them via CARGO_MANIFEST_DIR/../../contracts/.
  contractsSrc = ../../admin/contracts;

  # core-rs/build.rs reads this to generate the claw catalog at compile time.
  manifestSrc = ../../claws/manifest.yml;

  # household-rs/build.rs reads this to embed the emoji-security-code
  # wordlist CSV. The CSV lives inside admin/rust/household-rs/data/ so
  # plain `cargo build` resolves it via build.rs's CARGO_MANIFEST_DIR
  # fallback. We still pin the absolute path here so the Nix sandbox
  # resolves the file deterministically (the same recipe used for
  # `manifestSrc` above).
  emojiWordlistSrc = ../../admin/rust/household-rs/data/emoji-security-code-wordlist.csv;

  commonArgs = {
    inherit src;
    pname = packageName;
    version = "0.1.1";

    cargoExtraArgs = pkgs.lib.concatStringsSep " " (
      [ "--workspace" "--no-default-features" ]
      ++ map (member: "--exclude ${member}") excludedMembers
    );

    # Native build inputs (available at build time).
    nativeBuildInputs = with pkgs; [
      pkg-config
      jq
      binutils
      # ring (via russh) needs a C compiler and perl for its build script
      perl
    ];

    # Libraries linked at runtime.
    buildInputs = with pkgs; [
      # russh → ring needs these
      openssl
      # household-rs → keyring → dbus-secret-service (persistent secret storage on Linux)
      dbus
    ];

    # rusqlite "bundled" feature compiles SQLite from C source.
    # No system SQLite headers needed.

    # core-rs/build.rs uses CLAWS_MANIFEST_YML to find manifest.yml in the
    # Nix sandbox (the repo-relative ../../../ path doesn't exist here).
    CLAWS_MANIFEST_YML = manifestSrc;

    # household-rs/build.rs uses THEYOS_EMOJI_WORDLIST to find the CSV;
    # without this the relative include_str! path escapes the sandbox.
    THEYOS_EMOJI_WORDLIST = emojiWordlistSrc;

    # The repository Cargo config deliberately leaves this empty so a Nix
    # host path cannot leak into OCI/release builds. Nix supplies the real
    # target-aware pkg-config root here.
    PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";

    # Contract tests expect admin/contracts/ at ../../contracts/ relative to
    # each crate's CARGO_MANIFEST_DIR. In the Nix sandbox the workspace is at
    # /build/source/, so tests look for /build/contracts/.
    preConfigure = ''
      ln -s ${contractsSrc} $NIX_BUILD_TOP/contracts
    '';
  };

  # Phase 1: build all dependencies (cached separately from workspace source).
  depsOnly = craneLib.buildDepsOnly commonArgs;

in
  # Phase 2: build the workspace itself (uses cached deps).
  craneLib.buildPackage (commonArgs // {
    cargoArtifacts = depsOnly;

    postInstall = ''
      mkdir -p "$out/bin"
      for executable in server theyos-llm-proxy soyeht vmrunner_ipc fc-ssh store-ipc terminal-ipc imagebuilder; do
        if [ -x "target/release/$executable" ]; then
          install -m 0755 "target/release/$executable" "$out/bin/$executable"
        fi
      done
      test -x "$out/bin/server"
      test -x "$out/bin/theyos-llm-proxy"
      for executable in "$out"/bin/*; do
        if strings "$executable" | grep -Eiq \
          'RevalidatedCapability|ConsumedCapability|PointOfUsePermit|owner_present|/api/v1/mobile/claw-vpn/(owner|offers|sessions|rendezvous)'; then
          echo "Phase 0 marker found in $executable" >&2
          exit 1
        fi
        name="$(basename "$executable")"
        depfile="target/release/$name.d"
        test -f "$depfile"
        if [ "$name" != server ] && [ "$name" != theyos-llm-proxy ]; then
          if grep -Eiq 'server-rs/src|llm-proxy-rs/src|mobile_claw_vpn|product_a_phase0' "$depfile"; then
            echo "Phase 0 helper depfile reaches an authority source: $name" >&2
            exit 1
          fi
        fi
      done
      server_contract="$($out/bin/server --owner-present-phase0-contract)"
      proxy_contract="$($out/bin/theyos-llm-proxy --owner-present-phase0-contract)"
      echo "$server_contract" | jq -e '
        .authority == "none"
        and .production_activation == false
        and .third_target_injection_seam_compiled == false
        and .generic_ip_tunnel_backend_compiled == false
        and .generic_ip_tunnel_store_accepts_resource == false
        and .generic_ip_tunnel_env_accepts_resource == false
        and .declared_product_a_routes == ["/claw-vpn/status"]
      ' >/dev/null
      echo "$proxy_contract" | jq -e '
        .authority == "none"
        and .production_activation == false
        and .allowed_requests == [
          {"method":"GET","path":"/api/v1/mobile/claw-vpn/status"},
          {"method":"HEAD","path":"/api/v1/mobile/claw-vpn/status"}
        ]
      ' >/dev/null
      executables_json='{}'
      for executable in "$out"/bin/*; do
        test -f "$executable"
        test -x "$executable"
        name="$(basename "$executable")"
        case "$name" in
          server) classification="phase0-contract-server" ;;
          theyos-llm-proxy) classification="phase0-contract-http-boundary" ;;
          *) classification="phase0-helper-depfile-and-marker-closure-v1" ;;
        esac
        sha256="$(sha256sum "$executable" | cut -d' ' -f1)"
        depfile_sha256="$(sha256sum "target/release/$name.d" | cut -d' ' -f1)"
        executables_json="$(jq -c \
          --arg name "$name" \
          --arg sha256 "$sha256" \
          --arg depfile_sha256 "$depfile_sha256" \
          --arg classification "$classification" \
          '. + {($name): {sha256:$sha256,depfile_sha256:$depfile_sha256,classification:$classification}}' \
          <<< "$executables_json")"
      done
      jq -n -S \
        --arg flake_lock_sha256 "${flakeLockSha256}" \
        --argjson executables "$executables_json" \
        '{schema:"theyos-phase0-nix-runtime-manifest-v1",flake_lock_sha256:$flake_lock_sha256,executables:$executables,owner_present_authority:"none",production_activation:false,artifact_contract:"all-published-nix-executables-v1"}' \
        > "$out/phase0-runtime-manifest.json"
    '';

    # Skip tests that assume a normal Linux filesystem (fail in Nix sandbox):
    #   - which_binary_finds_sh: /bin/sh doesn't exist in sandbox
    #   - test_init_panic_handler_creates_dir: sandbox path restrictions
    # Tests are run by CI (backend-ci.yml) and `cargo test --workspace`.
    # Many tests assume a normal Linux filesystem (external binaries on PATH,
    # /bin/sh, node, writable dirs) which the Nix sandbox doesn't provide.
    doCheck = false;
  })
