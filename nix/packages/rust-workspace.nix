# Rust workspace build using crane.
# Can produce either the runtime subset or the full builder workspace,
# depending on `excludedMembers`.
{ pkgs, craneLib, packageName ? "theyos-admin", excludedMembers ? [ "vmrunner-macos-rs" ] }:

let
  # Use crane's cleanCargoSource plus extra filters for non-Rust assets that
  # crates pull in via include_str!:
  #   - .html files (e.g. server-rs/.../privacy.html)
  #   - anything under an `assets/` directory (e.g.
  #     rootfsbuilder-rs/assets/how-to-publish.md)
  src = pkgs.lib.cleanSourceWith {
    src = ../../admin/rust;
    filter = path: type:
      (craneLib.filterCargoSources path type)
      || (builtins.match ".*\\.html$" path != null)
      || (builtins.match ".*/assets/.*" path != null);
  };

  # Contract test fixtures live at admin/contracts/ (sibling of admin/rust/).
  # Tests resolve them via CARGO_MANIFEST_DIR/../../contracts/.
  contractsSrc = ../../admin/contracts;

  # core-rs/build.rs reads this to generate the claw catalog at compile time.
  manifestSrc = ../../claws/manifest.yml;

  commonArgs = {
    inherit src;
    pname = packageName;
    version = "0.1.1";

    cargoExtraArgs = pkgs.lib.concatStringsSep " " (
      [ "--workspace" ]
      ++ map (member: "--exclude ${member}") excludedMembers
    );

    # Native build inputs (available at build time).
    nativeBuildInputs = with pkgs; [
      pkg-config
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

    # Skip tests that assume a normal Linux filesystem (fail in Nix sandbox):
    #   - which_binary_finds_sh: /bin/sh doesn't exist in sandbox
    #   - test_init_panic_handler_creates_dir: sandbox path restrictions
    # Tests are run by CI (backend-ci.yml) and `cargo test --workspace`.
    # Many tests assume a normal Linux filesystem (external binaries on PATH,
    # /bin/sh, node, writable dirs) which the Nix sandbox doesn't provide.
    doCheck = false;
  })
