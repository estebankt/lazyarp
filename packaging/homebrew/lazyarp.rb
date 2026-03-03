class Lazyarp < Formula
  desc "ARP-based network scanner with a terminal UI"
  homepage "https://github.com/estebankt/lazyarp"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/estebankt/lazyarp/releases/download/v#{version}/lazyarp-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "FILL_IN_AFTER_RELEASE"
    else
      url "https://github.com/estebankt/lazyarp/releases/download/v#{version}/lazyarp-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "FILL_IN_AFTER_RELEASE"
    end
  end

  def install
    bin.install "lazyarp"
  end

  def caveats
    <<~EOS
      lazyarp requires raw socket access. Run with sudo:
        sudo lazyarp
      Or grant the capability (Linux only):
        sudo setcap cap_net_raw+eip #{opt_bin}/lazyarp
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/lazyarp --version")
  end
end
