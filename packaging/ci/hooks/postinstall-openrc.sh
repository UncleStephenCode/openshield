#!/bin/sh
set -eu
/usr/libexec/openshield/ensure-group
# Deliberately do not rc-update add or start the service.
exit 0
