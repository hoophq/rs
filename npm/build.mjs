#!/usr/bin/env node
// Stamp a release version across all npm packages and cross-compile the rs
// binary for every supported platform into each package's bin/ directory.
// This is the single source of truth for the platform matrix.
//
//   node npm/build.mjs 1.2.3
//
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(`usage: node npm/build.mjs <X.Y.Z>  (got: ${version ?? "<nothing>"})`);
  process.exit(1);
}

// node platform/arch <-> Go GOOS/GOARCH. The package dir/name uses node's
// naming so the launcher can resolve `@hoophq/rs-${process.platform}-${process.arch}`.
const PLATFORMS = [
  { pkg: "rs-darwin-arm64", goos: "darwin", goarch: "arm64", bin: "rs" },
  { pkg: "rs-darwin-x64", goos: "darwin", goarch: "amd64", bin: "rs" },
  { pkg: "rs-linux-x64", goos: "linux", goarch: "amd64", bin: "rs" },
  { pkg: "rs-linux-arm64", goos: "linux", goarch: "arm64", bin: "rs" },
  { pkg: "rs-win32-x64", goos: "windows", goarch: "amd64", bin: "rs.exe" },
];

const readJSON = (p) => JSON.parse(readFileSync(p, "utf8"));
const writeJSON = (p, o) => writeFileSync(p, JSON.stringify(o, null, 2) + "\n");

// 1. Stamp each platform package version.
for (const plat of PLATFORMS) {
  const p = join(repoRoot, "npm", plat.pkg, "package.json");
  const pkg = readJSON(p);
  pkg.version = version;
  writeJSON(p, pkg);
}

// 2. Stamp the launcher and pin its optionalDependencies to this version.
const parentPath = join(repoRoot, "npm", "rs", "package.json");
const parent = readJSON(parentPath);
parent.version = version;
parent.optionalDependencies = Object.fromEntries(
  PLATFORMS.map((p) => [`@hoophq/${p.pkg}`, version]),
);
writeJSON(parentPath, parent);

// 3. Cross-compile. rs is pure Go (CGO-free), so every target builds from the
// host with no C toolchain.
const ldflags = `-s -w -X main.version=v${version}`;
for (const plat of PLATFORMS) {
  const outDir = join(repoRoot, "npm", plat.pkg, "bin");
  mkdirSync(outDir, { recursive: true });
  const out = join(outDir, plat.bin);
  console.log(`building ${plat.goos}/${plat.goarch} -> ${out}`);
  execFileSync("go", ["build", "-trimpath", "-ldflags", ldflags, "-o", out, "./cmd/rs"], {
    cwd: repoRoot,
    stdio: "inherit",
    env: { ...process.env, GOOS: plat.goos, GOARCH: plat.goarch, CGO_ENABLED: "0" },
  });
}

console.log(`\nstamped + built v${version} for ${PLATFORMS.length} platforms`);
