# Test container for theyOS NixOS installation E2E tests.
# Based on nixos/nix (Nix package manager on Alpine).
# Simulates a NixOS-like environment for testing install scripts.
FROM --platform=linux/amd64 nixos/nix:latest

# Enable flakes globally
RUN echo 'experimental-features = nix-command flakes' >> /etc/nix/nix.conf

# Create /etc/NIXOS to simulate NixOS
RUN touch /etc/NIXOS

# Install tools needed by the test scripts.
# Install in separate commands to avoid silent failures from priority conflicts.
RUN nix profile install nixpkgs#gnused 2>&1 || true
RUN nix profile install nixpkgs#openssl 2>&1 || true
RUN nix profile install nixpkgs#gnugrep --priority 7 2>&1 || true

# Pre-configure git (already in the image)
RUN git config --global user.email "test@test.com" && \
    git config --global user.name "Test" && \
    git config --global init.defaultBranch main

WORKDIR /root

CMD ["sleep", "3600"]
