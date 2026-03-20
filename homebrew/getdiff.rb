class Getdiff < Formula
  desc "Capture and upload agentic coding sessions to Diff"
  homepage "https://getdiff.now"
  version "0.1.4"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/getdiff/cli/releases/download/v#{version}/getdiff-aarch64-apple-darwin.tar.gz"
      sha256 "165f1a65eccf6ababb4e8dce1fdad67cbf6006ad472742e031a3fea8d12ed185"
    else
      url "https://github.com/getdiff/cli/releases/download/v#{version}/getdiff-x86_64-apple-darwin.tar.gz"
      sha256 "12b133706ba31a621f6be786c94626298242d329d35dcf31cd17a11eade3d81c"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/getdiff/cli/releases/download/v#{version}/getdiff-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "2b0e75700d55534febf8a38705126ec1a7125604f397ccdcb0c41e7d9cf979d2"
    else
      url "https://github.com/getdiff/cli/releases/download/v#{version}/getdiff-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "936679bbfda0a2019bd31cc30cfab4940494aff19fd7cc574d4ed5bd3c6b8199"
    end
  end

  def install
    bin.install "getdiff"
  end

  service do
    run [opt_bin/"getdiff", "watch"]
    keep_alive true
    log_path var/"log/getdiff.log"
    error_log_path var/"log/getdiff.log"
    working_dir HOMEBREW_PREFIX
  end

  test do
    assert_match "getdiff", shell_output("#{bin}/getdiff --version")
  end
end
