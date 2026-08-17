# (c) 2026 Suprath PS. All rights reserved.
# Homebrew Formula for AarchGate Zero-Trust npm Sandbox

class Aarchgate < Formula
  desc "Zero-Trust Micro-VM npm Package Sandbox for Apple Silicon"
  homepage "https://github.com/Suprath/ag-npm"
  url "https://github.com/Suprath/ag-npm.git", branch: "main"
  head "https://github.com/Suprath/ag-npm.git"
  license "MIT"

  depends_on :macos => :ventura
  depends_on :arch => :arm64
  depends_on "cmake" => :build
  depends_on "ninja" => :build

  def install
    system "./build.sh", "--release"

    bin.install "build/aarchgate_daemon"
    bin.install "build/aarchgate_monitor"
    bin.install "scripts/aarchgate"

    (libexec/"shims").install "scripts/npm-shim.sh" => "npm"
    (libexec/"shims").install "scripts/pnpm-shim.sh" => "pnpm"
    (libexec/"shims").install "scripts/yarn-shim.sh" => "yarn"
    (libexec/"shims").install "scripts/bun-shim.sh" => "bun"
    (libexec/"scripts").install "scripts/build_kernel_initrd.sh"

    # Ad-hoc codesign binary for Apple Virtualization.framework entitlements
    system "codesign", "--force", "--sign", "-", "--entitlements", "entitlements.plist", bin/"aarchgate_daemon"
  end

  def post_install
    system "#{bin}/aarchgate", "init"
  end

  test do
    assert_match "AarchGate", shell_output("#{bin}/aarchgate status")
  end
end
