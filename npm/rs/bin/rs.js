#!/usr/bin/env node
"use strict";

// Thin launcher: resolve the prebuilt rs binary from the platform package that
// matches this host (installed via optionalDependencies) and exec it
// transparently — forwarding argv, stdio and the exit code.
const { spawnSync } = require("child_process");

const pkg = `@hoophq/rs-${process.platform}-${process.arch}`;
const binName = process.platform === "win32" ? "rs.exe" : "rs";

let binPath;
try {
  binPath = require.resolve(`${pkg}/bin/${binName}`);
} catch {
  console.error(
    `rs: no prebuilt binary for ${process.platform}-${process.arch}.\n` +
      `The optional dependency "${pkg}" was not installed. If you installed ` +
      `with --no-optional / --ignore-optional, reinstall without it.`,
  );
  process.exit(1);
}

const result = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(`rs: failed to execute ${binPath}: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
