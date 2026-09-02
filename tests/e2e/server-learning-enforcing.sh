#!/bin/sh
set -eu

usage() {
    printf 'usage: %s {nftables|iptables} ABSOLUTE_ARTIFACT_DIRECTORY\n' "$0" >&2
}

[ "$#" -eq 2 ] || { usage; exit 2; }
backend=$1
artifact_directory=$2
case "$backend" in nftables|iptables) ;; *) usage; exit 2 ;; esac
case "$artifact_directory" in /*) ;; *) printf '%s\n' 'artifact directory must be absolute' >&2; exit 2 ;; esac
artifact_mode=${E2E_ARTIFACT_MODE:-binary}
case "$artifact_mode" in
    binary)
        [ -x "$artifact_directory/openshield-daemon" ] \
            || { printf '%s\n' 'missing daemon binary' >&2; exit 2; }
        daemon_path=/opt/openshield/openshield-daemon
        ;;
    package)
        [ -d "$artifact_directory" ] \
            || { printf '%s\n' 'missing package directory' >&2; exit 2; }
        package_count=$(find "$artifact_directory" -mindepth 1 -maxdepth 1 -type f ! -name '.*' | wc -l)
        [ "$package_count" -eq 1 ] \
            || { printf '%s\n' 'expected exactly one package artifact' >&2; exit 2; }
        [ -z "$(find "$artifact_directory" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ] \
            || { printf '%s\n' 'unsafe package artifact directory' >&2; exit 2; }
        [ -z "$(find "$artifact_directory" -mindepth 1 -maxdepth 1 -name '.*' -print -quit)" ] \
            || { printf '%s\n' 'hidden package artifacts are not allowed' >&2; exit 2; }
        expected_version=${EXPECTED_VERSION:?EXPECTED_VERSION is required in package mode}
        case "$expected_version" in
            ''|*[!0-9A-Za-z.+~-]*) printf '%s\n' 'unsafe EXPECTED_VERSION' >&2; exit 2 ;;
        esac
        daemon_path=/usr/bin/openshield-daemon
        ;;
    *)
        printf '%s\n' 'E2E_ARTIFACT_MODE must be binary or package' >&2
        exit 2
        ;;
esac
client_family=${CLIENT_FAMILY:-debian}
client_platform=${CLIENT_PLATFORM:-linux/amd64}
client_image=${CLIENT_IMAGE:-rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922}
server_image=${SERVER_IMAGE:-python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285}
case "$client_family" in
    debian|deb|fedora|el9|el10|opensuse|tumbleweed|alpine|arch) ;;
    *) printf '%s\n' 'unsupported E2E client family' >&2; exit 2 ;;
esac
case "$client_platform" in
    linux/amd64|linux/arm64|linux/386) ;;
    *) printf '%s\n' 'unsupported native E2E client platform' >&2; exit 2 ;;
esac
for image in "$client_image" "$server_image"; do
    case "$image" in
        ''|-*|*[!A-Za-z0-9._/:@-]*) printf '%s\n' 'unsafe E2E image' >&2; exit 2 ;;
    esac
    case "$image" in
        *@sha256:????????????????????????????????????????????????????????????????) ;;
        *) printf '%s\n' 'E2E images must be pinned by SHA-256 digest' >&2; exit 2 ;;
    esac
    image_digest=${image##*@sha256:}
    case "$image_digest" in
        *[!0-9a-f]*) printf '%s\n' 'invalid E2E image digest' >&2; exit 2 ;;
    esac
done

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
        exact_caps=$4
        daemon=$5
        temporary_status="${status_file}.tmp"
        if [ "$exact_caps" = true ]; then
            setpriv \
                --regid root --groups openshield \
                --bounding-set=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
                --inh-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
                --ambient-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
                -- "$daemon" >"$log_file" 2>&1 &
        else
            "$daemon" >"$log_file" 2>&1 &
        fi
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
        "$daemon_log" "$daemon_pid_file" "$daemon_exit_file" \
        "$use_exact_unit_capabilities" "$daemon_path"
}

install_fail_closed_preflight() {
    docker exec "$client" /bin/sh -c '
        log_file=$1
        daemon=$2
        if ! setpriv \
            --regid root --groups openshield \
            --bounding-set=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
            --inh-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
            --ambient-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
            -- "$daemon" --install-fail-closed \
            >"$log_file" 2>&1; then
            cat "$log_file" >&2
            exit 1
        fi
    ' openshield-fail-closed-preflight /tmp/openshield-preflight.log "$daemon_path"
}

assert_exact_unit_process_state() {
    docker exec "$client" /bin/sh -c '
        pid_file=$1
        pid=$(cat "$pid_file")
        case "$pid" in ""|*[!0-9]*) exit 1 ;; esac
        status=/proc/$pid/status
        observer_gid=$(getent group openshield | cut -d: -f3)
        expected_caps=0000000000083004
        [ -n "$observer_gid" ] && [ -r "$status" ]

        set -- $(sed -n "s/^Uid:[[:space:]]*//p" "$status")
        [ "$#" -eq 4 ] && [ "$1" = 0 ] && [ "$2" = 0 ] \
            && [ "$3" = 0 ] && [ "$4" = 0 ]
        set -- $(sed -n "s/^Gid:[[:space:]]*//p" "$status")
        [ "$#" -eq 4 ] && [ "$1" = 0 ] && [ "$2" = 0 ] \
            && [ "$3" = 0 ] && [ "$4" = 0 ]
        set -- $(sed -n "s/^Groups:[[:space:]]*//p" "$status")
        [ "$#" -eq 1 ] && [ "$1" = "$observer_gid" ]
        [ "$(sed -n "s/^NoNewPrivs:[[:space:]]*//p" "$status")" = 1 ]
        for field in CapInh CapPrm CapEff CapBnd CapAmb; do
            value=$(sed -n "s/^$field:[[:space:]]*//p" "$status")
            [ "$value" = "$expected_caps" ] || exit 1
        done
    ' openshield-unit-state "$daemon_pid_file" || {
        printf '%s\n' 'daemon process does not match the packaged systemd identity and capabilities' >&2
        return 1
    }
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
docker pull --platform "$client_platform" "$client_image" >/dev/null
docker pull "$server_image" >/dev/null
network_id=$(docker network create --label "$resource_label" "$network_name")
server_id=$(docker create --name "$server_name" --label "$resource_label" --network "$network_id" \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --security-opt label=disable \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
    "$server_image" python3 -m http.server 18081 --bind 0.0.0.0)
docker start "$server_id" >/dev/null

if [ "$artifact_mode" = package ]; then
    client_id=$(docker create --platform "$client_platform" \
        --name "$client_name" --label "$resource_label" --network "$network_id" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
        --security-opt no-new-privileges --security-opt label=disable \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --mount "type=bind,src=$artifact_directory,dst=/packages,readonly" \
        --mount "type=bind,src=$script_directory/ipc_client.py,dst=/opt/ipc_client.py,readonly" \
        "$client_image" sleep infinity)
else
    client_id=$(docker create --platform "$client_platform" \
        --name "$client_name" --label "$resource_label" --network "$network_id" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
        --security-opt no-new-privileges --security-opt label=disable \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --mount "type=bind,src=$artifact_directory,dst=/opt/openshield,readonly" \
        --mount "type=bind,src=$script_directory/ipc_client.py,dst=/opt/ipc_client.py,readonly" \
        "$client_image" sleep infinity)
fi
docker start "$client_id" >/dev/null
client=$client_id
server=$server_id

begin_stage 'provision firewall client'
use_exact_unit_capabilities=true
case "$client_family" in
    debian|deb)
        if [ "$backend" = nftables ]; then
            # Install both frontends: selecting nftables must demonstrate
            # preference, not just the absence of the compatibility backend.
            packages='nftables iptables curl netcat-openbsd python3 passwd util-linux'
        else
            packages='iptables curl netcat-openbsd python3 passwd util-linux'
        fi
        docker exec "$client" apt-get update >/dev/null
        # shellcheck disable=SC2086
        docker exec "$client" apt-get install -y --no-install-recommends $packages >/dev/null
        if [ "$artifact_mode" = package ]; then
            docker exec "$client" /bin/sh -c \
                'apt-get install -y --no-install-recommends /packages/*.deb' >/dev/null
        fi
        ;;
    fedora|el9|el10)
        docker exec "$client" dnf -y install \
            curl nmap-ncat python3 shadow-utils util-linux >/dev/null
        if [ "$backend" = nftables ]; then
            docker exec "$client" /bin/sh -c \
                'dnf -y install nftables iptables-nft || dnf -y install nftables iptables' \
                >/dev/null
        else
            docker exec "$client" /bin/sh -c \
                'dnf -y install iptables-nft || dnf -y install iptables' >/dev/null
        fi
        if [ "$artifact_mode" = package ]; then
            docker exec "$client" /bin/sh -c \
                'dnf -y --setopt=install_weak_deps=False install /packages/*.rpm' >/dev/null
        fi
        ;;
    opensuse|tumbleweed)
        if [ "$backend" = nftables ]; then
            # Keep legacy xtables installed so nftables activation exercises
            # alternate-backend inspection with the exact systemd capability set.
            packages='nftables iptables curl netcat-openbsd python3 shadow util-linux'
        else
            packages='iptables curl netcat-openbsd python3 shadow util-linux'
        fi
        docker exec "$client" zypper --non-interactive refresh >/dev/null
        # shellcheck disable=SC2086
        docker exec "$client" zypper --non-interactive install $packages >/dev/null
        if [ "$artifact_mode" = package ]; then
            docker exec "$client" /bin/sh -c \
                'zypper --non-interactive install --no-recommends --allow-unsigned-rpm /packages/*.rpm' \
                >/dev/null
        fi
        ;;
    alpine)
        [ "$backend" = nftables ] || {
            printf '%s\n' 'the released Alpine package requires nftables' >&2
            exit 2
        }
        docker exec "$client" apk add --no-cache \
            nftables iptables curl netcat-openbsd python3 shadow util-linux libc-utils >/dev/null
        if [ "$artifact_mode" = package ]; then
            docker exec "$client" /bin/sh -c \
                'apk add --allow-untrusted /packages/*.apk' >/dev/null
        fi
        ;;
    arch)
        [ "$backend" = nftables ] || {
            printf '%s\n' 'the released Arch package requires nftables' >&2
            exit 2
        }
        docker exec "$client" pacman -Syu --noconfirm --needed \
            nftables iptables-nft curl openbsd-netcat python shadow util-linux >/dev/null
        if [ "$artifact_mode" = package ]; then
            docker exec "$client" /bin/sh -c \
                'pacman -U --noconfirm /packages/*.pkg.tar.zst' >/dev/null
        fi
        ;;
esac
if [ "$artifact_mode" = binary ]; then
    docker exec "$client" groupadd --system openshield
else
    docker exec "$client" getent group openshield >/dev/null
    docker exec "$client" test -x "$daemon_path"
    [ "$(docker exec "$client" "$daemon_path" --version)" \
        = "openshield-daemon $expected_version" ] || {
        printf '%s\n' 'installed daemon version does not match the release' >&2
        exit 1
    }
fi
docker exec "$client" useradd --system --no-create-home --shell /bin/false observer
docker exec "$client" useradd --system --no-create-home --shell /bin/false outsider
docker exec "$client" usermod --append --groups openshield observer

if [ "$backend" = nftables ]; then
    docker exec "$client" sh -c \
        'command -v nft >/dev/null && command -v iptables-save >/dev/null' || {
        printf '%s\n' 'nftables preference scenario does not have both backends installed' >&2
        exit 1
    }
else
    if docker exec "$client" sh -c 'command -v nft >/dev/null'; then
        printf '%s\n' 'iptables fallback scenario unexpectedly has nftables installed' >&2
        exit 1
    fi
    docker exec "$client" sh -c 'command -v iptables-save >/dev/null' || {
        printf '%s\n' 'iptables fallback scenario has no xtables frontend' >&2
        exit 1
    }
fi

begin_stage 'install systemd-equivalent fail-closed preflight'
install_fail_closed_preflight

begin_stage 'start daemon and select backend'
start_daemon /tmp/openshield.log
wait_for_daemon_ready /tmp/openshield.log 'initial daemon'
assert_exact_unit_process_state
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
observer_gid=$(docker exec "$client" getent group openshield | cut -d: -f3)
socket_gid=$(docker exec "$client" stat -c '%g' /run/openshield/observe.sock)
[ -n "$observer_gid" ] && [ "$socket_gid" = "$observer_gid" ] || {
    printf '%s\n' 'observation socket does not have the openshield group' >&2
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
udp_command=$(docker exec "$client" /bin/sh -c 'command -v nc')
udp_executable=$(docker exec "$client" readlink -f "$udp_command")
case "$udp_executable" in
    /*) ;;
    *) printf '%s\n' 'cannot resolve the UDP client executable' >&2; exit 1 ;;
esac
case "$udp_executable" in
    *[!A-Za-z0-9._/-]*)
        printf '%s\n' 'unsafe UDP client executable path' >&2
        exit 1
        ;;
esac
udp_payload=openshield-udp-e2e

run_udp_client() {
    docker exec "$client" /bin/sh -c '
        payload=$1
        executable=$2
        source_port=$3
        server_address=$4
        server_port=$5
        printf "%s" "$payload" \
            | "$executable" -u -w 2 -p "$source_port" "$server_address" "$server_port"
    ' openshield-udp-client \
        "$udp_payload" "$udp_executable" 19000 "$server_ip" 18082
}

docker exec "$client" curl --fail --silent --show-error --max-time 5 \
    "http://$server_ip:18081/" >/dev/null
if ! udp_reply=$(run_udp_client); then
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
if ! udp_reply=$(run_udp_client); then
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
udp_reply=$(run_udp_client || true)
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
if ! udp_reply=$(run_udp_client); then
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
assert_exact_unit_process_state
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
