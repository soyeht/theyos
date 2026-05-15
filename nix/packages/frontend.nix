# React + Vite frontend build.
# Produces built web assets (index.html, JS, CSS) in $out/.
#
# Uses importNpmLock to derive dependency fetches from package-lock.json
# integrity hashes — no manual npmDepsHash to maintain.
{ pkgs }:

pkgs.stdenv.mkDerivation {
  pname = "theyos-frontend";
  version = "0.1.1";
  src = ../../admin/frontend;

  nativeBuildInputs = [
    pkgs.nodejs
    pkgs.importNpmLock.npmConfigHook
  ];

  npmDeps = pkgs.importNpmLock {
    npmRoot = ../../admin/frontend;
  };

  # Vite's config uses outDir: "../web" which escapes the Nix sandbox.
  # Override to build into ./dist instead.
  buildPhase = ''
    runHook preBuild
    npx tsc -b
    npx vite build --outDir ./dist
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp -r dist/* $out/
    runHook postInstall
  '';

  doCheck = false;
}
