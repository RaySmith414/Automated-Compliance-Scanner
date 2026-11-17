#!/usr/bin/env bash
# Runs INSIDE a disposable Ubuntu container or root file system, never on a real host.
#
#   run_state.sh baseline   stock Ubuntu plus OpenSSH server
#   run_state.sh hardened   the same host after applying the remediation each check recommends
#
# It installs what the scan needs, prepares the state, runs the scanner and
# compares the verdicts with tests/containers/expected.json. The repository must
# be available at /src. Start the container with a noexec,nosuid,nodev tmpfs on
# /tmp for the hardened state (see .github/workflows/ci.yml).
set -euo pipefail
state="${1:?usage: run_state.sh baseline|hardened}"
export DEBIAN_FRONTEND=noninteractive

apt-get update -q >/dev/null
apt-get install -y -q --no-install-recommends \
    python3 python3-yaml python3-jinja2 python3-rich openssh-server kmod systemd procps passwd login >/dev/null
mkdir -p /run/sshd   # created by the ssh service on a booted host

if [ "$state" = "hardened" ]; then
    apt-get install -y -q --no-install-recommends rsyslog >/dev/null
    sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/; s/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs
    useradd -D -f 30
    mkdir -p /etc/ssh/sshd_config.d /etc/systemd/journald.conf.d
    printf 'PermitRootLogin no\nPermitEmptyPasswords no\nPasswordAuthentication no\nMaxAuthTries 4\n' \
        > /etc/ssh/sshd_config.d/10-hardening.conf
    printf '[Journal]\nCompress=yes\nStorage=persistent\n' > /etc/systemd/journald.conf.d/10-cis.conf
    systemctl enable rsyslog >/dev/null 2>&1 || true
fi

cd /src
out="$(mktemp -d)/scan.json"
set +e
python3 -m scanner --quiet --output json -f "$out" --find-timeout 300
code=$?
set -e
echo "scanner exit code: $code"
python3 tests/containers/compare.py "$state" "$out"
