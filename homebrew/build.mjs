#!/usr/bin/env node
// Cross-compile rs for the platforms Homebrew supports, package each build as a
// tar.gz, and render the tap formula (rs.rb) with the archive checksums. This is
// the single source of truth for the brew platform matrix and formula content.
//
//   node homebrew/build.mjs 1.2.3
//
// Everything lands in homebrew/dist/:
//   rs_<version>_<os>_<arch>.tar.gz   uploaded to the GitHub release
//   rs.rb                             copied into the hoophq/homebrew-tap repo
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const distDir = join(here, "dist");

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(`usage: node homebrew/build.mjs <X.Y.Z>  (got: ${version ?? "<nothing>"})`);
  process.exit(1);
}

// Homebrew only needs macOS and Linux. The keys map to the formula's
// on_macos/on_linux + on_arm/on_intel selector blocks; the values map to Go's
// GOOS/GOARCH. Windows is intentionally absent (npm covers it instead).
const PLATFORMS = [
  { key: "macosArm", os: "darwin", arch: "arm64", goos: "darwin", goarch: "arm64" },
  { key: "macosIntel", os: "darwin", arch: "amd64", goos: "darwin", goarch: "amd64" },
  { key: "linuxArm", os: "linux", arch: "arm64", goos: "linux", goarch: "arm64" },
  { key: "linuxIntel", os: "linux", arch: "amd64", goos: "linux", goarch: "amd64" },
];

const repo = "hoophq/rs";
const tag = `v${version}`;
// Match npm/build.mjs so `rs -version` reports the same v-prefixed string.
const ldflags = `-s -w -X main.version=${tag}`;

rmSync(distDir, { recursive: true, force: true });
mkdirSync(distDir, { recursive: true });

const sha = {};
for (const p of PLATFORMS) {
  const buildDir = join(distDir, `${p.os}_${p.arch}`);
  mkdirSync(buildDir, { recursive: true });
  const binPath = join(buildDir, "rs");
  console.log(`building ${p.goos}/${p.goarch}`);
  execFileSync("go", ["build", "-trimpath", "-ldflags", ldflags, "-o", binPath, "./cmd/rs"], {
    cwd: repoRoot,
    stdio: "inherit",
    env: { ...process.env, GOOS: p.goos, GOARCH: p.goarch, CGO_ENABLED: "0" },
  });

  const archive = `rs_${version}_${p.os}_${p.arch}.tar.gz`;
  const archivePath = join(distDir, archive);
  // -C keeps the binary at the archive root so the formula does bin.install "rs".
  execFileSync("tar", ["-czf", archivePath, "-C", buildDir, "rs"], { stdio: "inherit" });
  rmSync(buildDir, { recursive: true, force: true });

  sha[p.key] = createHash("sha256").update(readFileSync(archivePath)).digest("hex");
  console.log(`packaged ${archive}  ${sha[p.key]}`);
}

const url = (p) =>
  `https://github.com/${repo}/releases/download/${tag}/rs_${version}_${p.os}_${p.arch}.tar.gz`;
const [macosArm, macosIntel, linuxArm, linuxIntel] = PLATFORMS;

const formula = `class Rs < Formula
  desc "Local PII and secrets risk scanner for AI coding sessions"
  homepage "https://github.com/${repo}"
  version "${version}"
  license "MIT"

  on_macos do
    on_arm do
      url "${url(macosArm)}"
      sha256 "${sha.macosArm}"
    end
    on_intel do
      url "${url(macosIntel)}"
      sha256 "${sha.macosIntel}"
    end
  end

  on_linux do
    on_arm do
      url "${url(linuxArm)}"
      sha256 "${sha.linuxArm}"
    end
    on_intel do
      url "${url(linuxIntel)}"
      sha256 "${sha.linuxIntel}"
    end
  end

  def install
    bin.install "rs"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/rs -version")
  end
end
`;

writeFileSync(join(distDir, "rs.rb"), formula);
console.log(`\nwrote ${join(distDir, "rs.rb")} for ${PLATFORMS.length} platforms`);
