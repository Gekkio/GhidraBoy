#!/bin/bash
set -euo pipefail

GHIDRA_ZIP="${GHIDRA_VERSION}_${GHIDRA_BUILD_DATE}.zip"

cd "${HOME}"
curl -sSL "https://ghidra-sre.org/${GHIDRA_VERSION}_${GHIDRA_BUILD_DATE}.zip" -O

echo "${GHIDRA_SHA256} ${GHIDRA_ZIP}" | sha256sum -c
unzip "${GHIDRA_ZIP}"
