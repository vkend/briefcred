# Homebrew formula for briefcred.
#
# Lives here rather than in a tap repository so it is reviewed alongside the
# code it installs; publishing copies this file into the tap. The `url` and
# `sha256` below are filled in by the release workflow, which knows the tag and
# has just computed the checksum.
class Briefcred < Formula
  desc "Local credential broker for AI agents and developer tooling"
  homepage "https://github.com/briefcred/briefcred"
  url "https://github.com/briefcred/briefcred/releases/download/v0.1.0/briefcred-0.1.0-macos-universal.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license any_of: ["MIT", "Apache-2.0"]
  version "0.1.0"

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

  # The LaunchAgent, expressed the way Homebrew wants it. `brew services start
  # briefcred` writes a plist equivalent to the one `briefcred service install`
  # generates: same program, same label shape, same log destinations.
  #
  # `run_type :immediate` with `keep_alive` is the LaunchAgent's `RunAtLoad`
  # plus `KeepAlive`: the daemon has to be up before the first agent asks it
  # for a credential, and a broker that stays down after a crash is one whose
  # every profile has silently stopped working.
  service do
    run [opt_bin/"briefcred-daemon"]
    keep_alive true
    run_type :immediate
    log_path "#{Dir.home}/Library/Application Support/briefcred/logs/daemon.log"
    error_log_path "#{Dir.home}/Library/Application Support/briefcred/logs/daemon.log"
  end

  def caveats
    <<~EOS
      briefcred needs two things before it can broker anything:

        briefcred install --trust-ca    # installs the per-machine root CA
        briefcred profile bootstrap     # writes a profile and stores its master

      Installing the CA needs sudo, and is what lets the proxy terminate TLS
      for the subprocesses you wrap. Nothing else on the machine trusts it.

      Start the daemon with `brew services start briefcred`, or let
      `briefcred install` write the LaunchAgent itself if you would rather it
      were not managed by Homebrew.
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
