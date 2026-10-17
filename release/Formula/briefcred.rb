# Homebrew formula for briefcred.
#
# Lives here rather than in a tap repository so it is reviewed alongside the
# code it installs.
#
# The `url` and `sha256` below are placeholders: the checksum of a release that
# has not been built yet does not exist. The release workflow runs
# `release/scripts/stamp-formula.sh` over this file, which rewrites exactly
# those two lines from the tarball it just built, and uploads the result as a
# release asset named `briefcred.rb`. Copying that asset into the tap
# repository is a separate, manual act — the tap is its own repository, created
# out of band, and the release workflow holds no token for it.
#
# `crates/briefcred-e2e/tests/release_scripts.rs` asserts that stamping changes
# those two lines and leaves every other byte alone.
class Briefcred < Formula
  desc "Local credential broker for AI agents and developer tooling"
  homepage "https://github.com/vkend/briefcred"
  url "https://github.com/vkend/briefcred/releases/download/v0.1.0/briefcred-0.1.0-macos-universal.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license any_of: ["MIT", "Apache-2.0"]

  # A bottle would be a second copy of the same universal binaries. The release
  # tarball is already built for both architectures and notarised, so pouring
  # from it is the whole install.
  depends_on :macos

  def install
    # Every binary, not just the two a user types. The daemon spawns
    # `briefcred-helper-*` by name from the directory beside its own
    # executable, so a formula that installed only `briefcred` and
    # `briefcred-daemon` would produce a broker that starts perfectly well and
    # cannot mint anything.
    bin.install "bin/briefcred"
    bin.install "bin/briefcred-daemon"
    bin.install "bin/briefcred-hook"
    bin.install "bin/briefcred-helper-postgres-dynamic"
    bin.install "bin/briefcred-helper-aws-sts"

    doc.install "README.md" if File.exist?("README.md")
    doc.install "CHANGELOG.md" if File.exist?("CHANGELOG.md")
  end

  # No `service` block, on purpose. `brew services` would load a second
  # LaunchAgent, `homebrew.mxcl.briefcred`, beside the
  # `io.github.vkend.briefcred` one `briefcred install` writes, and the two
  # daemons would fight over one socket. `briefcred install` is the only way in
  # because it also does what a `service` block cannot: the CA, the starter
  # config, and waiting until the daemon is actually listening.
  #
  # No `version` either: Homebrew reads it from the `url`, which the release
  # workflow stamps. A literal here would be a third line the stamp does not
  # touch, left saying 0.1.0 forever.

  def caveats
    <<~EOS
      Start the daemon and trust its root CA (it asks for your password once):

        briefcred install --trust-ca
        briefcred profile bootstrap

      The CA is what lets the proxy terminate TLS for the subprocesses you
      wrap. Nothing else on the machine trusts it.

      After `brew upgrade briefcred`, move the running daemon onto the new
      binary without dropping a session:

        briefcred daemon upgrade

      Do not use `brew services` for briefcred; `briefcred install` manages
      the LaunchAgent.
    EOS
  end

  test do
    # Version, because it is the one command that needs no daemon, no profile,
    # no keychain and no CA — anything else here would be testing the
    # developer's machine rather than the install.
    assert_match version.to_s, shell_output("#{bin}/briefcred --version")

    # The schema command exercises rather more: it loads the profile types and
    # serialises them, so a binary that installed but cannot run at all fails
    # here rather than the first time somebody needs it.
    schema = shell_output("#{bin}/briefcred profile schema")
    assert_match "\"title\": \"Profile\"", schema

    # Every helper is present and runnable. This is the check that catches the
    # install having quietly shipped four binaries instead of five.
    %w[
      briefcred-daemon
      briefcred-hook
      briefcred-helper-postgres-dynamic
      briefcred-helper-aws-sts
    ].each do |binary|
      assert_predicate bin/binary, :executable?
    end
  end
end
