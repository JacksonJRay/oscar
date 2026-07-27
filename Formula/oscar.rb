# Homebrew formula for oscar (GitHub Releases).
#
# Install from this repo as a tap:
#   brew tap JacksonJRay/oscar https://github.com/JacksonJRay/oscar
#   brew install oscar
#
# Or one-shot:
#   brew install --formula https://raw.githubusercontent.com/JacksonJRay/oscar/main/Formula/oscar.rb
#
# After cutting a release, update `url` + `sha256` for your arch (see SHA256SUMS
# on the GitHub Release). Dual-arch users can use `on_arm` / `on_intel` blocks.

class Oscar < Formula
  desc "Multi-cloud Native Dredger — agentic CLI for AWS/GCP/Azure/K8s"
  homepage "https://github.com/JacksonJRay/oscar"
  version "0.1.2"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/JacksonJRay/oscar/releases/download/v0.1.2/oscar-v0.1.2-aarch64-apple-darwin.tar.gz"
      # Update from release SHA256SUMS after tagging:
      sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_SHA256SUMS"
    end
    on_intel do
      url "https://github.com/JacksonJRay/oscar/releases/download/v0.1.2/oscar-v0.1.2-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_SHA256SUMS"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/JacksonJRay/oscar/releases/download/v0.1.2/oscar-v0.1.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_SHA256SUMS"
    end
    on_intel do
      url "https://github.com/JacksonJRay/oscar/releases/download/v0.1.2/oscar-v0.1.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_RELEASE_SHA256SUMS"
    end
  end

  def install
    bin.install "oscar"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/oscar --version")
  end
end
