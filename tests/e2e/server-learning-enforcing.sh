#!/bin/sh
set -eu

usage() {
    printf 'usage: %s {nftables|iptables} ABSOLUTE_BINARY_DIRECTORY\n' "$0" >&2
}

[ "$#" -eq 2 ] || { usage; exit 2; }
backend=$1
binary_directory=$2
case "$backend" in nftables|iptables) ;; *) usage; exit 2 ;; esac
case "$binary_directory" in /*) ;; *) printf '%s\n' 'binary directory must be absolute' >&2; exit 2 ;; esac
[ -x "$binary_directory/openshield-daemon" ] || { printf '%s\n' 'missing daemon binary' >&2; exit 2; }

command -v docker >/dev/null 2>&1 || {
    printf '%s\n' 'docker is not installed' >&2
    exit 1
}
docker_host=$(docker context inspect --format '{{(index .Endpoints "docker").Host}}' 2>/dev/null) || {
    printf '%s\n' 'cannot inspect the active Docker context' >&2
    exit 1
}
case "$docker_host" in
    unix:///*) ;;
    *)
        printf 'refusing non-local Docker endpoint: %s\n' "$docker_host" >&2
        exit 1
        ;;
esac

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
temporary_directory=$(mktemp -d /tmp/openshield-e2e.XXXXXX)
run_token=${temporary_directory##*/}
network_name="openshield-$run_token"
client_name="openshield-client-$run_token"
server_name="openshield-server-$run_token"
resource_label="org.openshield.e2e.run=$run_token"
network_id=
client_id=
server_id=
stage_name=initialization
daemon_pid_file=/tmp/openshield.pid
daemon_exit_file=/tmp/openshield.exit-status
daemon_wait_attempts=600

begin_stage() {
    stage_name=$1
    printf '==> OpenShield E2E (%s): %s\n' "$backend" "$stage_name"
}

wait_for_marker() {
    container=$1
    marker=$2
    description=$3
    if docker exec "$container" /bin/sh -c '
        marker=$1
        attempt=0
        while [ "$attempt" -lt 100 ]; do
            [ ! -f "$marker" ] || exit 0
            attempt=$((attempt + 1))
            sleep 0.1
        done
        exit 1
    ' openshield-marker-wait "$marker"; then
        return 0
    fi
    printf '%s did not become ready within 10 seconds\n' "$description" >&2
    return 1
}

dump_daemon_log() {
    daemon_log=$1
    docker exec "$client" cat "$daemon_log" >&2 || true
}

start_daemon() {
    daemon_log=$1
    docker exec "$client" rm -f \
        "$daemon_pid_file" "$daemon_exit_file" "${daemon_exit_file}.tmp"
    docker exec --detach "$client" /bin/sh -c '
        log_file=$1
        pid_file=$2
        status_file=$3
        temporary_status="${status_file}.tmp"
        /opt/openshield/openshield-daemon >"$log_file" 2>&1 &
        child_pid=$!
        printf "%s\n" "$child_pid" >"$pid_file"
        if wait "$child_pid"; then
            child_status=0
        else
            child_status=$?
        fi
        printf "%s\n" "$child_status" >"$temporary_status"
        mv -f "$temporary_status" "$status_file"
        exit "$child_status"
    ' openshield-daemon-supervisor \
        "$daemon_log" "$daemon_pid_file" "$daemon_exit_file"
}

wait_for_daemon_ready() {
    daemon_log=$1
    daemon_description=$2
    if docker exec "$client" /bin/sh -c '
        socket_path=$1
        status_file=$2
        maximum_attempts=$3
        attempt=0
        while [ "$attempt" -lt "$maximum_attempts" ]; do
            [ ! -s "$status_file" ] || exit 3
            [ ! -S "$socket_path" ] || exit 0
            attempt=$((attempt + 1))
            sleep 0.1
        done
        exit 2
    ' openshield-daemon-ready-wait \
        /run/openshield/control.sock "$daemon_exit_file" "$daemon_wait_attempts"; then
        return 0
    else
        daemon_wait_status=$?
    fi
    dump_daemon_log "$daemon_log"
    if [ "$daemon_wait_status" -eq 3 ]; then
        daemon_status=$(docker exec "$client" cat "$daemon_exit_file" 2>/dev/null || true)
        printf '%s exited before readiness (status %s)\n' \
            "$daemon_description" "${daemon_status:-unknown}" >&2
    else
        printf '%s did not become ready within 60 seconds\n' "$daemon_description" >&2
    fi
    return 1
}

wait_for_daemon_exit() {
    daemon_log=$1
    daemon_description=$2
    if ! docker exec "$client" /bin/sh -c '
        status_file=$1
        maximum_attempts=$2
        attempt=0
        while [ "$attempt" -lt "$maximum_attempts" ]; do
            [ ! -s "$status_file" ] || exit 0
            attempt=$((attempt + 1))
            sleep 0.1
        done
        exit 1
    ' openshield-daemon-exit-wait "$daemon_exit_file" "$daemon_wait_attempts"; then
        dump_daemon_log "$daemon_log"
        printf '%s did not exit within 60 seconds\n' "$daemon_description" >&2
        return 1
    fi
    daemon_status=$(docker exec "$client" cat "$daemon_exit_file" 2>/dev/null || true)
    case "$daemon_status" in
        0) return 0 ;;
        ''|*[!0-9]*)
            dump_daemon_log "$daemon_log"
            printf '%s produced an invalid exit status: %s\n' \
                "$daemon_description" "${daemon_status:-empty}" >&2
            ;;
        *)
            dump_daemon_log "$daemon_log"
            printf '%s exited unsuccessfully with status %s\n' \
                "$daemon_description" "$daemon_status" >&2
            ;;
    esac
    return 1
}

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        printf 'OpenShield E2E failed during stage "%s" (%s)\n' "$stage_name" "$backend" >&2
        if [ -n "$client_id" ]; then
            docker exec "$client_id" sh -c \
                'printf "%s\n" "--- runtime ---"
                 uname -a 2>/dev/null || true
                 cat /tmp/openshield.exit-status /var/lib/openshield/state.json 2>/dev/null || true
                 printf "%s\n" "--- daemon logs ---"
                 cat /tmp/openshield.log /tmp/openshield-restart.log 2>/dev/null || true
                 for save in \
                     /usr/sbin/iptables-legacy-save /usr/sbin/ip6tables-legacy-save \
                     /usr/sbin/iptables-nft-save /usr/sbin/ip6tables-nft-save; do
                     [ ! -x "$save" ] || for table in mangle filter; do
                         printf "%s\n" "--- $save -t $table ---"
                         "$save" -c -t "$table" 2>&1 || true
                     done
                 done' >&2 \
                || true
        fi
    fi
    [ -z "$client_id" ] || docker rm -f "$client_id" >/dev/null 2>&1 || true
    [ -z "$server_id" ] || docker rm -f "$server_id" >/dev/null 2>&1 || true
    [ -z "$network_id" ] || docker network rm "$network_id" >/dev/null 2>&1 || true
    case "$temporary_directory" in
        /tmp/openshield-e2e.*) rm -rf -- "$temporary_directory" ;;
        *) printf 'refusing unsafe temporary cleanup: %s\n' "$temporary_directory" >&2 ;;
    esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

begin_stage 'create isolated containers'
network_id=$(docker network create --label "$resource_label" "$network_name")
server_id=$(docker create --name "$server_name" --label "$resource_label" --network "$network_id" \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --security-opt label=disable \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
    python:3.13-slim python3 -m http.server 18081 --bind 0.0.0.0)
docker start "$server_id" >/dev/null

client_id=$(docker create --name "$client_name" --label "$resource_label" --network "$network_id" \
    --cap-add NET_ADMIN --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
    --security-opt no-new-privileges --security-opt label=disable \
    --env PYTHONDONTWRITEBYTECODE=1 \
    --mount "type=bind,src=$binary_directory,dst=/opt/openshield,readonly" \
    --mount "type=bind,src=$script_directory/ipc_client.py,dst=/opt/ipc_client.py,readonly" \
    rust:1.98.0-bookworm sleep infinity)
docker start "$client_id" >/dev/null
client=$client_id
server=$server_id

begin_stage 'provision firewall client'
if [ "$backend" = nftables ]; then
    packages='nftables curl netcat-openbsd python3 passwd util-linux'
else
    packages='iptables curl netcat-openbsd python3 passwd util-linux'
fi
docker exec "$client" apt-get update >/dev/null
# shellcheck disable=SC2086
docker exec "$client" apt-get install -y --no-install-recommends $packages >/dev/null
docker exec "$client" groupadd --system openshield
docker exec "$client" useradd --system --no-create-home --shell /usr/sbin/nologin observer
docker exec "$client" useradd --system --no-create-home --shell /usr/sbin/nologin outsider
docker exec "$client" usermod --append --groups openshield observer

begin_stage 'start daemon and select backend'
start_daemon /tmp/openshield.log
wait_for_daemon_ready /tmp/openshield.log 'initial daemon'
if [ "$backend" = nftables ]; then
    expected_backend=nftables
else
    expected_backend=iptables/ip6tables
fi
docker exec "$client" grep -Fq "firewall_backend=\"$expected_backend\"" \
    /tmp/openshield.log || {
        docker exec "$client" cat /tmp/openshield.log >&2 || true
        printf 'daemon did not select expected backend: %s\n' "$expected_backend" >&2
        exit 1
    }

begin_stage 'verify IPC access control'
status=$(docker exec "$client" python3 /opt/ipc_client.py status)
case "$status" in *'"mode": "learning"'*) ;; *) printf 'unexpected initial status: %s\n' "$status" >&2; exit 1 ;; esac
# `docker exec --user` does not consistently initialize supplementary groups
# across Docker/OCI versions. `runuser` exercises the actual group membership
# installed inside the isolated client instead of weakening the assertion.
docker exec "$client" runuser -u observer -- python3 /opt/ipc_client.py status >/dev/null
if docker exec "$client" runuser -u outsider -- python3 /opt/ipc_client.py status >/dev/null 2>&1; then
    printf '%s\n' 'a user outside the openshield group read observation IPC' >&2
    exit 1
fi
if docker exec "$client" runuser -u observer -- python3 /opt/ipc_client.py set-mode enforcing \
    >/dev/null 2>&1; then
    printf '%s\n' 'an openshield group member reached privileged control IPC' >&2
    exit 1
fi

server_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$server")
client_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$client")
case "$server_ip:$client_ip" in
    *[!0-9.:]*) printf '%s\n' 'unsafe container address' >&2; exit 1 ;;
esac

begin_stage 'learn outbound TCP and UDP applications'
docker exec --detach "$server" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 18082))
open("/tmp/openshield-udp-ready", "w", encoding="ascii").close()
while True:
    data, address = s.recvfrom(4096)
    s.sendto(data, address)
'
wait_for_marker "$server" /tmp/openshield-udp-ready 'UDP echo server'
udp_executable=$(docker exec "$client" readlink -f /bin/nc)
case "$udp_executable" in
    /*) ;;
    *) printf '%s\n' 'cannot resolve the UDP client executable' >&2; exit 1 ;;
esac
udp_payload=openshield-udp-e2e

docker exec "$client" curl --fail --silent --show-error --max-time 5 \
    "http://$server_ip:18081/" >/dev/null
if ! udp_reply=$(docker exec "$client" sh -c \
    "printf '%s' '$udp_payload' | /bin/nc -u -w 2 -p 19000 '$server_ip' 18082"); then
    printf '%s\n' 'UDP echo command failed during Learning' >&2
    exit 1
fi
[ "$udp_reply" = "$udp_payload" ] || {
    printf '%s\n' 'UDP echo failed during Learning' >&2
    exit 1
}

attempt=0
while [ "$attempt" -lt 50 ]; do
    if docker exec "$client" python3 /opt/ipc_client.py assert-learned \
        /usr/bin/curl "$server_ip" 18081; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
[ "$attempt" -lt 50 ] || exit 1
attempt=0
while [ "$attempt" -lt 50 ]; do
    if docker exec "$client" python3 /opt/ipc_client.py assert-learned \
        "$udp_executable" "$server_ip" 18082; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
[ "$attempt" -lt 50 ] || exit 1

begin_stage 'enforce learned outbound rules'
docker exec "$client" python3 /opt/ipc_client.py set-mode enforcing >/dev/null
docker exec "$client" curl --fail --silent --show-error --max-time 5 \
    "http://$server_ip:18081/" >/dev/null
if ! udp_reply=$(docker exec "$client" sh -c \
    "printf '%s' '$udp_payload' | /bin/nc -u -w 2 -p 19000 '$server_ip' 18082"); then
    printf '%s\n' 'learned UDP command failed during Enforcing' >&2
    exit 1
fi
[ "$udp_reply" = "$udp_payload" ] || {
    printf '%s\n' 'learned UDP application did not receive its Enforcing reply' >&2
    exit 1
}

# An OpenShield allow must not bypass a later DROP owned by another firewall.
begin_stage 'verify downstream firewall DROP precedence'
if [ "$backend" = iptables ]; then
    if docker exec "$client" /usr/sbin/iptables-legacy-save -t filter 2>/dev/null \
        | grep -Fq -- '-A OUTPUT -j OPENSHIELD_OUT'; then
        iptables_command=/usr/sbin/iptables-legacy
        iptables_save=/usr/sbin/iptables-legacy-save
    else
        iptables_command=/usr/sbin/iptables
        iptables_save=/usr/sbin/iptables-save
    fi
    docker exec "$client" "$iptables_save" -c -t mangle \
        | grep -m1 -E -- ' -A OUTPUT ' \
        | grep -Eq -- '^\[[0-9]+:[0-9]+\] -A OUTPUT -j OPENSHIELD_MARK$' || {
        printf '%s\n' 'OpenShield mangle sanitizer is not the first OUTPUT rule' >&2
        exit 1
    }
    docker exec "$client" "$iptables_save" -c -t filter \
        | grep -Eq -- '^\[[1-9][0-9]*:[0-9]+\] -A OPENSHIELD_APP_TCP -j CONNMARK ' || {
        printf '%s\n' 'NF_REPEAT did not reach the post-queue TCP authorization chain' >&2
        exit 1
    }
    docker exec "$client" "$iptables_save" -c -t filter \
        | grep -Eq -- '^\[[1-9][0-9]*:[0-9]+\] -A OPENSHIELD_APP_PKT -j CONNMARK ' || {
        printf '%s\n' 'NF_REPEAT did not reach the post-queue UDP authorization chain' >&2
        exit 1
    }
    docker exec "$client" "$iptables_command" --wait 5 -A OUTPUT -p tcp -d "$server_ip" \
        --dport 18081 -m comment --comment openshield-e2e-downstream -j DROP
    docker exec "$client" "$iptables_command" --wait 5 -A OUTPUT -p udp -d "$server_ip" \
        --dport 18082 -m comment --comment openshield-e2e-downstream -j DROP
else
    docker exec "$client" nft add table inet openshield_e2e_downstream
    docker exec "$client" nft add chain inet openshield_e2e_downstream output \
        '{ type filter hook output priority 10; policy accept; }'
    docker exec "$client" nft add rule inet openshield_e2e_downstream output \
        ip daddr "$server_ip" tcp dport 18081 drop
    docker exec "$client" nft add rule inet openshield_e2e_downstream output \
        ip daddr "$server_ip" udp dport 18082 drop
fi
if docker exec "$client" curl --fail --silent --show-error --max-time 2 \
    "http://$server_ip:18081/" >/dev/null 2>&1; then
    printf '%s\n' 'an OpenShield allow bypassed a downstream firewall DROP' >&2
    exit 1
fi
udp_reply=$(docker exec "$client" sh -c \
    "printf '%s' '$udp_payload' | /bin/nc -u -w 2 -p 19000 '$server_ip' 18082" || true)
if [ "$udp_reply" = "$udp_payload" ]; then
    printf '%s\n' 'an OpenShield UDP allow bypassed a downstream firewall DROP' >&2
    exit 1
fi
if [ "$backend" = iptables ]; then
    docker exec "$client" "$iptables_command" --wait 5 -D OUTPUT -p tcp -d "$server_ip" \
        --dport 18081 -m comment --comment openshield-e2e-downstream -j DROP
    docker exec "$client" "$iptables_command" --wait 5 -D OUTPUT -p udp -d "$server_ip" \
        --dport 18082 -m comment --comment openshield-e2e-downstream -j DROP
else
    docker exec "$client" nft delete table inet openshield_e2e_downstream
fi
docker exec "$client" curl --fail --silent --show-error --max-time 5 \
    "http://$server_ip:18081/" >/dev/null
if ! udp_reply=$(docker exec "$client" sh -c \
    "printf '%s' '$udp_payload' | /bin/nc -u -w 2 -p 19000 '$server_ip' 18082"); then
    printf '%s\n' 'UDP echo command failed after downstream DROP removal' >&2
    exit 1
fi
[ "$udp_reply" = "$udp_payload" ] || {
    printf '%s\n' 'UDP echo did not recover after downstream DROP removal' >&2
    exit 1
}

# Reuse the exact UDP conntrack tuple from another executable. The outbound
# reset must remove the previous nc generation mark before Python is denied;
# otherwise the echo reply would expose a stale-connmark authorization bypass.
begin_stage 'verify application and connmark isolation'
if docker exec "$client" python3 -c \
    "import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 19000))
s.settimeout(2)
s.sendto(b'$udp_payload', ('$server_ip', 18082))
assert s.recvfrom(4096)[0] == b'$udp_payload'" \
    >/dev/null 2>&1; then
    printf '%s\n' 'a different executable inherited the learned UDP connmark' >&2
    exit 1
fi

if docker exec "$client" python3 -c \
    "import urllib.request; urllib.request.urlopen('http://$server_ip:18081/', timeout=2).read()" \
    >/dev/null 2>&1; then
    printf '%s\n' 'a different executable bypassed the learned application rule' >&2
    exit 1
fi

begin_stage 'verify inbound default deny and explicit allow'
docker exec --detach "$client" python3 -c '
from http.server import HTTPServer, SimpleHTTPRequestHandler
server = HTTPServer(("0.0.0.0", 18080), SimpleHTTPRequestHandler)
open("/tmp/openshield-http-ready", "w", encoding="ascii").close()
server.serve_forever()
'
wait_for_marker "$client" /tmp/openshield-http-ready 'inbound HTTP server'
if docker exec "$server" python3 -c \
    "import urllib.request; urllib.request.urlopen('http://$client_ip:18080/', timeout=2).read()" \
    >/dev/null 2>&1; then
    printf '%s\n' 'inbound traffic passed without an allow rule' >&2
    exit 1
fi
docker exec "$client" python3 /opt/ipc_client.py allow-inbound-tcp 18080 >/dev/null
docker exec "$server" python3 -c \
    "import urllib.request; urllib.request.urlopen('http://$client_ip:18080/', timeout=5).read()" \
    >/dev/null || {
        printf '%s\n' 'explicit inbound allow rule did not admit TCP traffic' >&2
        exit 1
    }

begin_stage 'graceful shutdown and fail-closed policy'
daemon_pid=$(docker exec "$client" cat "$daemon_pid_file")
case "$daemon_pid" in ''|*[!0-9]*) printf '%s\n' 'invalid daemon pid' >&2; exit 1 ;; esac
docker exec "$client" kill -TERM "$daemon_pid"
wait_for_daemon_exit /tmp/openshield.log 'initial daemon'
if docker exec "$client" test -S /run/openshield/control.sock; then
    printf '%s\n' 'daemon left the control socket after process exit' >&2
    exit 1
fi
docker exec "$client" python3 -c \
    'import json; assert json.load(open("/var/lib/openshield/state.json", encoding="utf-8"))["mode"] == "enforcing"'
if docker exec "$client" curl --fail --silent --show-error --max-time 2 \
    "http://$server_ip:18081/" >/dev/null 2>&1; then
    printf '%s\n' 'graceful shutdown did not leave kernel BlockAll active' >&2
    exit 1
fi

begin_stage 'restart with persisted policy'
start_daemon /tmp/openshield-restart.log
wait_for_daemon_ready /tmp/openshield-restart.log 'restarted daemon'
status=$(docker exec "$client" python3 /opt/ipc_client.py status)
case "$status" in *'"mode": "enforcing"'*) ;; *) printf 'unexpected restart status: %s\n' "$status" >&2; exit 1 ;; esac
docker exec "$client" curl --fail --silent --show-error --max-time 5 \
    "http://$server_ip:18081/" >/dev/null || {
        printf '%s\n' 'persisted outbound rule did not recover after daemon restart' >&2
        exit 1
    }
daemon_pid=$(docker exec "$client" cat "$daemon_pid_file")
case "$daemon_pid" in ''|*[!0-9]*) printf '%s\n' 'invalid restarted daemon pid' >&2; exit 1 ;; esac
docker exec "$client" kill -TERM "$daemon_pid"
wait_for_daemon_exit /tmp/openshield-restart.log 'restarted daemon'
if docker exec "$client" test -S /run/openshield/control.sock; then
    printf '%s\n' 'restarted daemon left the control socket after process exit' >&2
    exit 1
fi

printf 'PASS server Learning -> UDP/TCP Enforcing -> inbound allow -> restart (%s)\n' "$backend"
