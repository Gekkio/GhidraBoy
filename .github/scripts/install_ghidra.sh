#!/bin/bash
set -euo pipefail

GHIDRA_ZIP="ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD_DATE}.zip"

cd "${HOME}"
curl -sSL "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}" -O

echo "${GHIDRA_SHA256} ${GHIDRA_ZIP}" | sha256sum -c
unzip "${GHIDRA_ZIP}"
mv "${HOME}/ghidra_${GHIDRA_VERSION}_PUBLIC" "${HOME}/ghidra"
