# frozen_string_literal: true

# Constitution-IV justification (plan.md "Complexity Tracking"):
# Stub kept (not deleted) so `brew upgrade theyos` shows the redirect message
# instead of an opaque "formula not found" error to existing users.
# Full deletion scheduled for v0.3.0 once telemetry confirms zero brew installs.
class Theyos < Formula
  desc "Soyeht — DEPRECATED via Homebrew; see https://soyeht.com/install"
  homepage "https://soyeht.com/install"
  version "0.1.8"
  url "data:,"  # no download needed — install block exits immediately
  sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  def install
    odie <<~MSG
      Soyeht has moved — the Homebrew formula is no longer supported.

      Download the latest Soyeht.app from: https://soyeht.com/install

      If you are on Linux, the install script is:
        curl -fsSL https://soyeht.com/install | sh
    MSG
  end
end
