# Firecracker guest kernel (vmlinux-6.1.155).
# Official pre-built binary from Firecracker CI (Amazon Linux microVM kernel).
# URL pattern: s3://spec.ccfc.min/firecracker-ci/v{major}.{minor}/{arch}/vmlinux-{version}
{ pkgs }:

pkgs.fetchurl {
  url = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155";
  hash = "sha256-4g5G0MNsVcDRAU6yBXYXGz89kiJg2feSAXrv9Trz1PI=";
  name = "vmlinux";
}
