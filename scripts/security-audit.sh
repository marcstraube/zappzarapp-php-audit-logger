#!/usr/bin/env bash
#
# Security audit of runtime (non-dev) dependencies, mirroring the Node repo's
# `pnpm audit --prod`. This library ships no runtime Composer deps (`require` is
# just php + ext-pdo), so the non-dev set is empty. `composer audit --no-dev`
# errors on an empty set ("No installed packages found", exit 1), and
# `--locked --no-dev` does not help (Composer falls back to the installed path
# on an empty non-dev set). Guard so an empty set passes green like pnpm does;
# the audit runs automatically once runtime deps exist.
#
# Single source of truth: both the `composer security` script and the CI
# `security` job run this file, so local and CI checks can never drift.
set -euo pipefail

if [ -n "$(composer show --locked --no-dev 2>/dev/null)" ]; then
  composer audit --locked --no-dev
else
  echo "No runtime dependencies to audit."
fi
