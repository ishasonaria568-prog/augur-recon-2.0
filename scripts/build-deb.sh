#!/usr/bin/env bash
# ==============================================================================
# AUGUR RECON 2.0 — Debian / Kali Linux Package Builder
# Developer: Isha Sonaria (https://github.com/ishasonaria568-prog)
# Generates: dist/augur-recon_2.0.0_all.deb
# ==============================================================================

set -euo pipefail

PACKAGE_NAME="augur-recon"
VERSION="2.0.0"
ARCHITECTURE="all"
DEB_FILE="${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}.deb"
DIST_DIR="$(pwd)/dist"
STAGING_DIR="$(pwd)/.deb-staging"

echo -e "\e[31;1m[AUGUR RECON 2.0]\e[0m Building Debian Package for Kali Linux & Debian Systems..."
echo "Package: ${PACKAGE_NAME} v${VERSION} (${ARCHITECTURE})"

# Clean previous build artifacts
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}"
mkdir -p "${DIST_DIR}"

# 1. Build Frontend & Assets
echo "[*] Building frontend assets with Vite..."
npm run build

# 2. Construct Debian Package Directory Hierarchy
echo "[*] Constructing filesystem layout..."
INSTALL_DIR="${STAGING_DIR}/usr/lib/augur-recon"
BIN_DIR="${STAGING_DIR}/usr/bin"
SYSTEMD_DIR="${STAGING_DIR}/lib/systemd/system"
DOC_DIR="${STAGING_DIR}/usr/share/doc/augur-recon"
DEBIAN_DIR="${STAGING_DIR}/DEBIAN"

mkdir -p "${INSTALL_DIR}"
mkdir -p "${BIN_DIR}"
mkdir -p "${SYSTEMD_DIR}"
mkdir -p "${DOC_DIR}"
mkdir -p "${DEBIAN_DIR}"

# 3. Copy Application Assets to /usr/lib/augur-recon
cp -r dist "${INSTALL_DIR}/dist"
cp -r src "${INSTALL_DIR}/src"
cp -r bin "${INSTALL_DIR}/bin"
cp server.ts "${INSTALL_DIR}/server.ts"
cp package.json "${INSTALL_DIR}/package.json"
cp tsconfig.json "${INSTALL_DIR}/tsconfig.json"
cp .env.example "${INSTALL_DIR}/.env.example"

# 4. Create /usr/bin/augur Binary Launcher
cat << 'EOF' > "${BIN_DIR}/augur"
#!/usr/bin/env bash
# AUGUR RECON 2.0 Launcher
NODE_PATH="/usr/lib/augur-recon"
cd "${NODE_PATH}"
exec npx tsx src/cli/index.ts "$@"
EOF
chmod 755 "${BIN_DIR}/augur"

# 5. Create Systemd Service Unit for optional daemon web server mode
cat << 'EOF' > "${SYSTEMD_DIR}/augur-recon.service"
[Unit]
Description=AUGUR RECON 2.0 Attack Surface Intelligence Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/lib/augur-recon
ExecStart=/usr/bin/augur serve --port 3000 --host 0.0.0.0
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "${SYSTEMD_DIR}/augur-recon.service"

# 6. Copy Copyright and Documentation
cat << EOF > "${DOC_DIR}/copyright"
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: augur-recon
Upstream-Contact: Isha Sonaria <https://github.com/ishasonaria568-prog>
Source: https://github.com/ishasonaria568-prog/augur-recon

Files: *
Copyright: 2026 Isha Sonaria
License: Apache-2.0
EOF
chmod 644 "${DOC_DIR}/copyright"

# 7. Create DEBIAN/control file
cat << EOF > "${DEBIAN_DIR}/control"
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCHITECTURE}
Depends: nodejs (>= 20.0.0), npm
Maintainer: Isha Sonaria <https://github.com/ishasonaria568-prog>
Description: AI-Augmented Attack Surface Intelligence & Network Reconnaissance
 AUGUR RECON 2.0 is a CLI-first, local-first cybersecurity reconnaissance
 platform engineered for authorized penetration testing and attack-surface
 assessments. It features concurrent TCP/UDP scanning, protocol-aware
 banner grabbing, TLS inspection, DNS enumeration, SQLite scan history,
 deterministic attack-surface diffing, multi-format reporting (JSON, CSV,
 Markdown, HTML), and optional Gemini AI security analysis.
EOF
chmod 644 "${DEBIAN_DIR}/control"

# 8. Create DEBIAN/postinst (post-installation script)
cat << 'EOF' > "${DEBIAN_DIR}/postinst"
#!/bin/sh
set -e
chmod 755 /usr/bin/augur
echo "AUGUR RECON 2.0 installed successfully."
echo "Execute 'augur --help' to start reconnaissance."
exit 0
EOF
chmod 755 "${DEBIAN_DIR}/postinst"

# 9. Build Debian Package using dpkg-deb
echo "[*] Packaging debian archive with dpkg-deb..."
dpkg-deb --build --root-owner-group "${STAGING_DIR}" "${DIST_DIR}/${DEB_FILE}"

# Cleanup staging directory
rm -rf "${STAGING_DIR}"

echo -e "\e[32;1m[✓] Package built successfully:\e[0m ${DIST_DIR}/${DEB_FILE}"
echo "Verify installation using: sudo dpkg -i dist/${DEB_FILE}"
