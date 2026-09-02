#!/bin/sh
set -eu

# Create the read-only observation group and the shared xtables lock without
# enabling or starting the firewall service.
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/openshield.conf
else
    /usr/libexec/openshield/ensure-group
fi

if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/openshield.conf
fi

# Containers used by CI usually do not boot systemd, so daemon-reload is best-effort.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
