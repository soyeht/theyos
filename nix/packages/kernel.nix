# Firecracker guest kernel (vmlinux-6.1.155) with built-in TUN support.
#
# This is source-built from the same mainline kernel version as Firecracker's
# prebuilt CI artifact, using the upstream Firecracker CI x86_64 config plus
# CONFIG_TUN=y/CONFIG_TUN_VNET_CROSS_LE=y. Product A per-Claw VPN needs TUN
# inside Linux claws before any userspace VPN agent can open an interface.
{ pkgs }:

let
  kernelVersion = "6.1.155";
  kernelSrc = pkgs.fetchurl {
    url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${kernelVersion}.tar.xz";
    hash = "sha256-wpOHru4IX7y9kSNiJLnfgFBjusQ2Fedc6ixrKWBKXHM=";
  };
in
pkgs.stdenv.mkDerivation {
  pname = "firecracker-kernel";
  version = kernelVersion;

  src = kernelSrc;

  nativeBuildInputs = with pkgs; [
    bc
    bison
    elfutils
    flex
    ncurses
    openssl
    perl
    pkg-config
  ];

  configurePhase = ''
    cp ${./firecracker-kernel-x86_64.config} .config
    make olddefconfig

    for opt in TUN TUN_VNET_CROSS_LE; do
      sed -i "s/# CONFIG_$opt is not set/CONFIG_$opt=y/" .config
      grep -q "^CONFIG_$opt=y" .config || echo "CONFIG_$opt=y" >> .config
    done

    # Firecracker never uses kexec in theyOS microVMs. Nix's current toolchain
    # fails in x86 purgatory linkage if these stay enabled in the upstream CI
    # config, so keep the unused kexec path off for this source build.
    for opt in KEXEC KEXEC_FILE KEXEC_CORE ARCH_HAS_KEXEC_PURGATORY; do
      sed -i "s/^CONFIG_$opt=y/# CONFIG_$opt is not set/" .config
    done
    make olddefconfig

    grep -q '^CONFIG_TUN=y' .config || {
      echo "CONFIG_TUN not enabled as builtin"
      exit 1
    }
    grep -q '^CONFIG_TUN_VNET_CROSS_LE=y' .config || {
      echo "CONFIG_TUN_VNET_CROSS_LE not enabled as builtin"
      exit 1
    }
    for opt in KEXEC KEXEC_FILE KEXEC_CORE ARCH_HAS_KEXEC_PURGATORY; do
      if grep -q "^CONFIG_$opt=y" .config; then
        echo "CONFIG_$opt was enabled by olddefconfig"
        exit 1
      fi
    done
  '';

  buildPhase = ''
    make -j$NIX_BUILD_CORES vmlinux
  '';

  # Keep the historical package contract: cfg.kernelPackage is a vmlinux file,
  # because nix/module.nix symlinks ${cfg.kernelPackage} directly to
  # firecracker/assets/vmlinux-6.1.155.
  installPhase = ''
    cp vmlinux "$out"
  '';

  dontStrip = true;
  dontFixup = true;
}
