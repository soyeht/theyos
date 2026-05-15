# Firecracker + jailer binaries (pre-built from GitHub releases).
# Version and SHA-256 match core-rs/src/constants.rs.
{ pkgs }:

let
  version = "v1.15.0";
  arch = if pkgs.stdenv.hostPlatform.isx86_64 then "x86_64" else "aarch64";
  sha256 = if pkgs.stdenv.hostPlatform.isx86_64
    then "00cadf7f21e709e939dc0c8d16e2d2ce7b975a62bec6c50f74b421cc8ab3cab4"
    else "58325e6c3c539482a412ec0b60e6f539c3320adebcf8179c7629d06736aee0bd";
in

pkgs.stdenv.mkDerivation {
  pname = "firecracker";
  inherit version;

  src = pkgs.fetchurl {
    url = "https://github.com/firecracker-microvm/firecracker/releases/download/${version}/firecracker-${version}-${arch}.tgz";
    inherit sha256;
  };

  # The tgz contains a top-level directory: release-v1.15.0-x86_64/
  # Inside it: firecracker-v1.15.0-x86_64, jailer-v1.15.0-x86_64
  unpackPhase = ''
    tar xzf $src
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp release-${version}-${arch}/firecracker-${version}-${arch} $out/bin/firecracker
    cp release-${version}-${arch}/jailer-${version}-${arch} $out/bin/jailer
    chmod +x $out/bin/*
  '';

  dontFixup = true;
}
