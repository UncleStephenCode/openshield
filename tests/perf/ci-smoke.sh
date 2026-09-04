#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C.UTF-8
export PYTHONDONTWRITEBYTECODE=1

readonly MAX_TIMEOUT_SECONDS=900
readonly MAX_JSON_BYTES=$((8 * 1024 * 1024))
readonly MAX_CSV_BYTES=$((16 * 1024 * 1024))
readonly MAX_MARKDOWN_BYTES=$((512 * 1024))
readonly MAX_LOG_BYTES=$((16 * 1024 * 1024))
readonly RUN_LABEL_KEY='org.openshield.perf.run'
output_directory_owned=false
run_cleanup_started=false
run_token=''

cleanup_current_run() {
    local exact_label
    local identifier
    local -a identifiers=()

    [[ "$run_cleanup_started" == false ]] || return 0
    run_cleanup_started=true
    [[ "$run_token" =~ ^[0-9a-f]{32}$ ]] || return 0
    command -v docker >/dev/null 2>&1 || return 0
    command -v timeout >/dev/null 2>&1 || return 0

    # The filter is only a first pass. Re-inspect every immutable Docker ID
    # and require the exact cryptographic token before deleting anything.
    mapfile -t identifiers < <(
        timeout --signal=TERM --kill-after=2s 10s \
            docker ps --all --quiet \
                --filter "label=${RUN_LABEL_KEY}=${run_token}" 2>/dev/null
    )
    for identifier in "${identifiers[@]}"; do
        [[ "$identifier" =~ ^[0-9a-f]{12,64}$ ]] || continue
        exact_label=$(
            timeout --signal=TERM --kill-after=2s 10s \
                docker inspect --type container \
                    --format '{{ index .Config.Labels "org.openshield.perf.run" }}' \
                    "$identifier" 2>/dev/null
        ) || continue
        [[ "$exact_label" == "$run_token" ]] || continue
        timeout --signal=TERM --kill-after=2s 20s \
            docker rm --force "$identifier" >/dev/null 2>&1 || true
    done

    identifiers=()
    mapfile -t identifiers < <(
        timeout --signal=TERM --kill-after=2s 10s \
            docker network ls --quiet \
                --filter "label=${RUN_LABEL_KEY}=${run_token}" 2>/dev/null
    )
    for identifier in "${identifiers[@]}"; do
        [[ "$identifier" =~ ^[0-9a-f]{12,64}$ ]] || continue
        exact_label=$(
            timeout --signal=TERM --kill-after=2s 10s \
                docker network inspect \
                    --format '{{ index .Labels "org.openshield.perf.run" }}' \
                    "$identifier" 2>/dev/null
        ) || continue
        [[ "$exact_label" == "$run_token" ]] || continue
        timeout --signal=TERM --kill-after=2s 20s \
            docker network rm "$identifier" >/dev/null 2>&1 || true
    done
}

on_exit() {
    local status=$?
    trap - EXIT TERM INT
    set +e
    cleanup_current_run
    exit "$status"
}

trap on_exit EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

preserve_failure_diagnostics() {
    local message=$1
    local base=${output_directory:-}
    local diagnostics_directory
    local entry
    local maximum_size
    local name
    local path
    local size
    [[ "$output_directory_owned" == true \
        && -n "$base" && -d "$base" && ! -L "$base" ]] || return 0
    diagnostics_directory="$base/failure-diagnostics"
    [[ ! -e "$diagnostics_directory" && ! -L "$diagnostics_directory" ]] || return 0
    install -d -m 0700 -- "$diagnostics_directory" || return 0
    printf '%s\n' "${message:0:4096}" \
        > "$diagnostics_directory/wrapper-error.txt"
    for entry in \
        "run.log:$MAX_LOG_BYTES" \
        "report.json:$MAX_JSON_BYTES" \
        "report.csv:$MAX_CSV_BYTES" \
        "overload.csv:$MAX_CSV_BYTES" \
        "report.md:$MAX_MARKDOWN_BYTES"; do
        name=${entry%%:*}
        maximum_size=${entry#*:}
        path="$base/$name"
        [[ -f "$path" && ! -L "$path" ]] || continue
        size=$(stat -c '%s' -- "$path" 2>/dev/null) || continue
        [[ "$size" =~ ^[0-9]+$ ]] || continue
        (( size > 0 && size <= maximum_size )) || continue
        install -m 0600 -- "$path" "$diagnostics_directory/$name" || return 0
    done
}

fail() {
    local message=$*
    printf 'performance CI smoke: %s\n' "$message" >&2
    preserve_failure_diagnostics "$message"
    exit 1
}

usage() {
    printf 'usage: %s ABSOLUTE_NEW_OUTPUT_DIRECTORY\n' "$0" >&2
}

[[ "$#" -eq 1 ]] || {
    usage
    exit 2
}

output_directory=$1
[[ "$output_directory" == /* ]] || fail 'output directory must be absolute'
[[ ! -e "$output_directory" && ! -L "$output_directory" ]] \
    || fail 'output directory must not already exist'

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_directory/../.." && pwd -P)
runner="$repository_root/tests/perf/run.py"
config="$repository_root/tests/perf/config/ci-smoke.json"

for required_command in awk docker grep install jq python3 sha256sum stat tee timeout; do
    command -v "$required_command" >/dev/null 2>&1 \
        || fail "required command is unavailable: $required_command"
done

for source_file in "$runner" "$script_directory/environment.py" "$config"; do
    [[ -f "$source_file" && ! -L "$source_file" && -r "$source_file" ]] \
        || fail "required input is not a readable regular non-symlink file: $source_file"
done
jq -e 'type == "object"' "$config" >/dev/null \
    || fail 'ci-smoke configuration is not a JSON object'
jq -e '
    .criteria.maximum_throughput_reduction_vs_baseline_percent == 10
    and .criteria.maximum_dut_pps_reduction_vs_baseline_percent == 10
    and .criteria.maximum_latency_increase_vs_baseline_percent == 10
    and .criteria.maximum_cgroup_cpu_increase_vs_baseline_percent == 10
    and .criteria.require_burst_capacity == true
    and .capacity_certification == false
' "$config" >/dev/null \
    || fail 'ci-smoke thresholds must be exactly 10 percent and burst capacity must be required'

daemon=${OPENSHIELD_DAEMON:-}
[[ "$daemon" == /* ]] || fail 'OPENSHIELD_DAEMON must be an absolute path'
[[ -f "$daemon" && ! -L "$daemon" && -x "$daemon" ]] \
    || fail 'OPENSHIELD_DAEMON must be an executable regular non-symlink file'

install -d -m 0700 -- "$output_directory"
output_directory_owned=true
run_log="$output_directory/run.log"
report_json="$output_directory/report.json"
report_csv="$output_directory/report.csv"
overload_csv="$output_directory/overload.csv"
report_markdown="$output_directory/report.md"

docker_host=$(timeout --signal=TERM --kill-after=5s 15s \
    docker context inspect --format '{{(index .Endpoints "docker").Host}}' 2>/dev/null) \
    || fail 'cannot inspect the active Docker context'
if [[ -n "${DOCKER_HOST:-}" && "$DOCKER_HOST" != unix:///* ]]; then
    fail "refusing DOCKER_HOST override: $DOCKER_HOST"
fi
case "$docker_host" in
    unix:///*) ;;
    *) fail "refusing non-local Docker endpoint: $docker_host" ;;
esac
docker_socket=${docker_host#unix://}
[[ "$docker_socket" == /* && -S "$docker_socket" ]] \
    || fail "Docker endpoint is not a local Unix socket: $docker_host"
timeout --signal=TERM --kill-after=5s 30s docker info >/dev/null 2>&1 \
    || fail 'the local Docker engine is unavailable'

run_token=$(python3 -I -B -S -c 'import secrets; print(secrets.token_hex(16))') \
    || fail 'cannot generate a private performance run token'
[[ "$run_token" =~ ^[0-9a-f]{32}$ ]] \
    || fail 'generated performance run token has an invalid format'
readonly run_token

timeout_seconds=${PERF_TIMEOUT_SECONDS:-$MAX_TIMEOUT_SECONDS}
[[ "$timeout_seconds" =~ ^[1-9][0-9]{1,2}$ ]] \
    || fail 'PERF_TIMEOUT_SECONDS must be a decimal integer without leading zeroes'
(( timeout_seconds >= 30 && timeout_seconds <= MAX_TIMEOUT_SECONDS )) \
    || fail "PERF_TIMEOUT_SECONDS must be between 30 and $MAX_TIMEOUT_SECONDS"

printf 'performance CI smoke: daemon sha256 %s\n' \
    "$(sha256sum -- "$daemon" | awk '{print $1}')"
printf 'performance CI smoke: hard timeout %s seconds\n' "$timeout_seconds"

set +e
{
    # Keep GNU timeout's separate process group.  It must terminate the runner
    # and every docker CLI child together; --foreground would only signal
    # run.py and a child retaining stdout could keep the pipeline alive.
    timeout --signal=TERM --kill-after=15s "${timeout_seconds}s" \
        python3 -I -B -S "$runner" \
            --config "$config" \
            --output-dir "$output_directory" \
            --run-token "$run_token"
    runner_status=$?
    if (( runner_status != 0 )); then
        printf 'performance CI smoke: runner status %s\n' "$runner_status"
        if [[ -f "$report_json" && ! -L "$report_json" ]]; then
            report_size=$(stat -c '%s' -- "$report_json" 2>/dev/null)
            if [[ "$report_size" =~ ^[0-9]+$ ]] \
                && (( report_size > 0 && report_size <= MAX_JSON_BYTES )); then
                printf 'performance CI smoke: bounded failure summary: '
                jq -c '
                    def short: if type == "string" then .[0:2048] else . end;
                    {
                        schema,
                        valid,
                        passed,
                        fatal_error: ((.fatal_error // null) | short),
                        backends: ([.backends[]? | {
                            name,
                            status,
                            reason: ((.reason // null) | short)
                        }] | .[0:8]),
                        failed_results: ([.results[]?
                            | select(.valid != true or .passed != true)
                            | {
                                backend,
                                policy,
                                mode,
                                profile,
                                phase,
                                valid,
                                passed,
                                unreliable_reasons,
                                failure_reasons,
                                safety_failure_reasons,
                                relative_performance_failure_reasons
                            }
                        ] | .[0:20]),
                        failed_overload: ([.overload_results[]?
                            | select(.valid != true or .passed != true)
                            | {
                                backend,
                                transport,
                                valid,
                                passed,
                                saturation,
                                validity_failure_reasons,
                                safety_failure_reasons,
                                recovery_failure_reasons
                            }
                        ] | .[0:8])
                    }
                ' "$report_json" || printf '%s\n' 'report.json is malformed'
            else
                printf 'performance CI smoke: report.json is empty or exceeds its size bound\n'
            fi
        else
            printf 'performance CI smoke: no safe report.json was produced\n'
        fi
    fi
    exit "$runner_status"
} 2>&1 \
    | LC_ALL=C awk -v limit="$MAX_LOG_BYTES" '
        BEGIN {
            marker = "[performance CI smoke: output truncated]"
            content_limit = limit - length(marker) - 1
            written = 0
            truncated = 0
        }
        {
            bytes = length($0) + 1
            if (written + bytes <= content_limit) {
                print
                written += bytes
            } else if (!truncated) {
                print marker
                written += length(marker) + 1
                truncated = 1
            }
        }
    ' \
    | tee "$run_log"
pipeline_status=("${PIPESTATUS[@]}")
set -e

[[ "${pipeline_status[1]}" -eq 0 && "${pipeline_status[2]}" -eq 0 ]] \
    || fail 'could not capture the performance runner output'
if [[ "${pipeline_status[0]}" -ne 0 ]]; then
    if [[ "${pipeline_status[0]}" -eq 124 ]]; then
        fail "performance runner exceeded the ${timeout_seconds}-second limit"
    fi
    fail "performance runner exited with status ${pipeline_status[0]}"
fi

validate_output_file() {
    local path=$1
    local maximum_size=$2
    local size
    [[ -f "$path" && ! -L "$path" ]] \
        || fail "missing regular non-symlink report: $path"
    size=$(stat -c '%s' -- "$path")
    [[ "$size" =~ ^[0-9]+$ ]] || fail "cannot determine report size: $path"
    (( size > 0 && size <= maximum_size )) \
        || fail "report has an invalid size ($size bytes): $path"
}

validate_output_file "$report_json" "$MAX_JSON_BYTES"
validate_output_file "$report_csv" "$MAX_CSV_BYTES"
validate_output_file "$overload_csv" "$MAX_CSV_BYTES"
validate_output_file "$report_markdown" "$MAX_MARKDOWN_BYTES"

allow_unsupported_iptables=$(jq -r '
    if has("allow_unsupported_iptables")
    then .allow_unsupported_iptables
    else false
    end
' "$config")
case "$allow_unsupported_iptables" in
    true|false) ;;
    *) fail 'allow_unsupported_iptables must be a JSON boolean' ;;
esac

jq -e --argjson allow_unsupported_iptables "$allow_unsupported_iptables" '
    . as $report
    | type == "object"
    and .schema == "openshield.perf.report.v1"
    and .valid == true
    and .passed == true
    and .criteria == .configuration.criteria
    and .criteria.maximum_throughput_reduction_vs_baseline_percent == 10
    and .criteria.maximum_dut_pps_reduction_vs_baseline_percent == 10
    and .criteria.maximum_latency_increase_vs_baseline_percent == 10
    and .criteria.maximum_cgroup_cpu_increase_vs_baseline_percent == 10
    and .criteria.require_burst_capacity == true
    and .configuration.criteria.require_burst_capacity == true
    and .configuration.capacity_certification == false
    and .harness.schema == "openshield.perf.harness-evidence.v1"
    and (.harness.manifest_sha256
        | type == "string" and test("^[0-9a-f]{64}$"))
    and (.harness.components | type == "array" and length == 10)
    and all(.harness.components[];
        (.path | type == "string" and length > 0)
        and (.size | type == "number" and . > 0 and . <= 4194304)
        and (.sha256 | type == "string" and test("^[0-9a-f]{64}$")))
    and (.environments | type == "array" and length == 2)
    and (([.environments[].backend] | sort) == ["iptables", "nftables"])
    and all(.environments[];
        .schema == "openshield.perf.environment.v1"
        and (.backend == "iptables" or .backend == "nftables")
        and .image_reference == $report.configuration.images.dut
        and (.image_id | type == "string" and test("^sha256:[0-9a-f]{64}$"))
        and (.os_release | type == "object" and .ID == "opensuse-tumbleweed")
        and (.uname | type == "string" and startswith("Linux "))
        and .machine == "x86_64"
        and (.repo_oss_repomd_sha256
            | type == "string" and test("^[0-9a-f]{64}$"))
        and (.rpm_manifest_sha256
            | type == "string" and test("^[0-9a-f]{64}$"))
        and (.rpm_nevra | type == "array" and length > 0)
        and .reproducibility.image_content_pinned == true
        and .reproducibility.repository_metadata_recorded == true
        and .reproducibility.cross_run_package_set_immutable == false)
    and (([.environments[].image_id] | unique | length) == 1)
    and (([.environments[].os_release] | unique | length) == 1)
    and (([.environments[].uname] | unique | length) == 1)
    and (([.environments[].repo_oss_repomd_sha256] | unique | length) == 1)
    and .environment_consistency.schema
        == "openshield.perf.environment-consistency.v1"
    and .environment_consistency.valid == true
    and (.environment_consistency.failure_reasons
        | type == "array" and length == 0)
    and .environment_consistency.package_delta.expected_nftables_delta_observed
        == true
    and .environment_consistency.package_delta.expected_nftables_only_package_names
        == ["libedit0", "libjansson4", "libnftables1", "nftables"]
    and .environment_consistency.package_delta.observed_nftables_only_package_names
        == ["libedit0", "libjansson4", "libnftables1", "nftables"]
    and (.environment_consistency.package_delta.nftables_only_nevra
        | type == "array" and length == 4)
    and (.environment_consistency.package_delta.iptables_only_nevra
        | type == "array" and length == 0)
    and .environment_consistency.package_delta.full_manifest_equality_required
        == false
    and (.backends | type == "array")
    and (([.backends[].name] | sort) == ["iptables", "nftables"])
    and all(.backends[];
        type == "object"
        and (.name == "iptables" or .name == "nftables")
        and (.status == "passed" or .status == "failed" or .status == "unsupported")
        and (.reason == null or (.reason | type == "string")))
    and any(.backends[]; .name == "nftables" and .status == "passed")
    and any(.backends[];
        .name == "iptables"
        and (.status == "passed"
            or ($allow_unsupported_iptables and .status == "unsupported")))
    and (.results | type == "array" and length > 0)
    and (.overload_results | type == "array")
    and all(.overload_results[];
        . as $overload
        | type == "object"
        and .schema == "openshield.perf.overload.v1"
        and (.backend == "iptables" or .backend == "nftables")
        and (.transport == "tcp" or .transport == "udp")
        and .mode == "enforcing"
        and .valid == true
        and .passed == true
        and .safety_pass == true
        and .resource_validity.valid == true
        and (.resource_validity.failure_reasons | type == "array" and length == 0)
        and .pressure_start_gate.schema == "openshield.perf.workload.v1"
        and .pressure_start_gate.event == "ready"
        and .pressure_start_gate.role == "client"
        and .pressure_start_gate.transport == .transport
        and .pressure_start_gate.start_gate == "stdin_line_v1"
        and (.pressure_start_gate.pid | type == "number" and . >= 1)
        and .network_liveness_preflight.passed == true
        and .saturation.proven == true
        and .saturation.timestamps_ordered == true
        and (.saturation.minimum_nfqueue_drops | type == "number" and . >= 1)
        and (.config.minimum_nfqueue_drops == .saturation.minimum_nfqueue_drops)
        and (.saturation.stall_drop_delta.total | type == "number")
        and (.saturation.stall_drop_delta.total >= .saturation.minimum_nfqueue_drops)
        and .identity_probe_during_stall.blocked_all == true
        and .identity_probe_during_stall.fail_open == false
        and .identity_probe_during_stall.liveness_passed == true
        and (.identity_probe_during_stall.attempts | type == "array")
        and (($overload.identity_probe_during_stall.attempts | length)
            == $overload.config.probe_attempts)
        and all(.identity_probe_during_stall.attempts[];
            .schema == "openshield.perf.workload.v1"
            and .event == "probe"
            and .role == "identity_probe"
            and .transport == $overload.transport
            and .probe_event_valid == true
            and .timeout_observed == true
            and .success == false
            and .exit_code == 2
            and .indeterminate == false
            and .blocked == true
            and .fail_open == false
            and .isolated_canary_server_alive == true
            and .liveness_before.passed == true
            and .liveness_before.server_alive == true
            and .liveness_after.passed == true
            and .liveness_after.server_alive == true)
        and (
            if .quarantine.reported == true
            then (
                .recovery_pass == null
                and .quarantine.occurred == true
                and .quarantine.kernel_block_all == true
                and .quarantine.black_box.valid == true
                and .quarantine.black_box.passed == true
                and .quarantine.black_box.structural_passed == true
                and .quarantine.black_box.timestamps_ordered == true
                and .quarantine.black_box.ipv4.passed == true
                and ((.quarantine.black_box.ipv4.probes | keys | sort)
                    == ["tcp", "udp"])
                and .quarantine.black_box.ipv4.probes.tcp.transport == "tcp"
                and .quarantine.black_box.ipv4.probes.udp.transport == "udp"
                and .quarantine.black_box.ipv6.available == false
                and .quarantine.black_box.ipv6.valid == false
                and .quarantine.black_box.ipv6.passed == false
                and .quarantine.black_box.status_before.mode == "block_all"
                and .quarantine.black_box.status_after.mode == "block_all"
                and .quarantine.black_box.kernel_before.inspected == true
                and .quarantine.black_box.kernel_before.block_all == true
                and .quarantine.black_box.kernel_after.inspected == true
                and .quarantine.black_box.kernel_after.block_all == true
                and all(.quarantine.black_box.ipv4.probes[];
                    .schema == "openshield.perf.workload.v1"
                    and .event == "probe"
                    and .role == "identity_probe"
                    and .probe_event_valid == true
                    and .timeout_observed == true
                    and .success == false
                    and .exit_code == 2
                    and .indeterminate == false
                    and .preflight_reachable == true
                    and .server_alive == true
                    and .peer_health_before.path == "canary-container-loopback"
                    and .peer_health_before.passed == true
                    and .peer_health_before.server_alive == true
                    and .peer_health_after.path == "canary-container-loopback"
                    and .peer_health_after.passed == true
                    and .peer_health_after.server_alive == true
                    and .blocked == true
                    and .fail_open == false)
                and .identity_probe_after_resume.skipped_due_to_reported_quarantine == true
            )
            else (
                .quarantine.reported == false
                and .recovery_pass == true
                and .network_liveness_after_resume.passed == true
                and .network_liveness_after_resume.before.server_alive == true
                and .network_liveness_after_resume.after.server_alive == true
                and .identity_probe_after_resume.schema
                    == "openshield.perf.workload.v1"
                and .identity_probe_after_resume.event == "probe"
                and .identity_probe_after_resume.role == "identity_probe"
                and .identity_probe_after_resume.transport == $overload.transport
                and .identity_probe_after_resume.probe_event_valid == true
                and .identity_probe_after_resume.timeout_observed == true
                and .identity_probe_after_resume.success == false
                and .identity_probe_after_resume.exit_code == 2
                and .identity_probe_after_resume.indeterminate == false
                and .identity_probe_after_resume.blocked == true
                and .identity_probe_after_resume.fail_open == false
            )
            end
        ))
    and all(.results[];
        type == "object"
        and (.backend == "iptables" or .backend == "nftables")
        and (.policy == "baseline"
            or .policy == "network_only"
            or .policy == "application_tcp"
            or .policy == "application_udp")
        and (.mode == null or .mode == "enforcing" or .mode == "learning")
        and (.profile | type == "string" and length > 0)
        and (.phase | type == "string" and length > 0)
        and (.phase_role == "warmup"
            or .phase_role == "ramp"
            or .phase_role == "steady"
            or .phase_role == "burst")
        and .valid == true
        and .passed == true
        and .safety_pass == true
        and (.capacity_pass | type == "boolean")
        and (.workload.metrics.errors | type == "number" and . == 0)
        and ([
            .dut_metrics.network.rx_pps,
            .dut_metrics.network.tx_pps,
            .dut_metrics.network.rx_mbps,
            .dut_metrics.network.tx_mbps,
            .peer_metrics.network.rx_pps,
            .peer_metrics.network.tx_pps,
            .peer_metrics.network.rx_mbps,
            .peer_metrics.network.tx_mbps,
            .dut_metrics.softirq.net_rx,
            .dut_metrics.softirq.net_tx,
            .peer_metrics.softirq.net_rx,
            .peer_metrics.softirq.net_tx,
            .dut_metrics.conntrack_count_start,
            .dut_metrics.conntrack_count_peak,
            .peer_metrics.conntrack_count_start,
            .peer_metrics.conntrack_count_peak
        ] | all(.[]; type == "number" and . >= 0))
        and (.dut_metrics.conntrack_count_peak
             >= .dut_metrics.conntrack_count_start)
        and (.peer_metrics.conntrack_count_peak
             >= .peer_metrics.conntrack_count_start)
        and ([
            .dut_metrics.network.rx_dropped,
            .dut_metrics.network.tx_dropped,
            .dut_metrics.network.rx_errors,
            .dut_metrics.network.tx_errors,
            .peer_metrics.network.rx_dropped,
            .peer_metrics.network.tx_dropped,
            .peer_metrics.network.rx_errors,
            .peer_metrics.network.tx_errors
        ] | all(.[]; type == "number" and . == 0))
        and (if .transport == "tcp"
             then ([.dut_metrics.tcp_retransmits, .peer_metrics.tcp_retransmits]
                   | all(.[]; type == "number" and . == 0))
             else ((.workload.metrics.reply_loss_ratio
                    | type == "number" and . == 0)
                   and .udp_scenario_accounting.valid == true
                   and .udp_scenario_accounting.matched == true
                   and .udp_scenario_accounting.packet_matched == true
                   and .udp_scenario_accounting.barrier_evidence_valid == true
                   and .udp_scenario_accounting.barriers_matched == true
                   and (.udp_scenario_accounting.client_barrier_errors
                        | type == "number" and . == 0)
                   and (.udp_scenario_accounting.packet_loss
                        | type == "number" and . == 0)
                   and (.udp_scenario_accounting.unexpected_packets
                        | type == "number" and . == 0))
             end)
        and (if .policy == "baseline"
             then true
             else ([
                 .dut_metrics.nfqueue.kernel_dropped,
                 .dut_metrics.nfqueue.user_dropped,
                 .daemon_log_events.terminal_queue_error_lower_bound,
                 .daemon_log_events.queue_overflow_lower_bound,
                 .daemon_log_events.attribution_timeout_lower_bound
             ] | all(.[]; type == "number" and . == 0))
             and .nfqueue_runtime_counters.valid == true
             and ([
                 .nfqueue_runtime_counters.before.queue_overflow,
                 .nfqueue_runtime_counters.before.attribution_timeout,
                 .nfqueue_runtime_counters.before.terminal_queue_error,
                 .nfqueue_runtime_counters.before.denied,
                 .nfqueue_runtime_counters.after.queue_overflow,
                 .nfqueue_runtime_counters.after.attribution_timeout,
                 .nfqueue_runtime_counters.after.terminal_queue_error,
                 .nfqueue_runtime_counters.after.denied,
                 .nfqueue_runtime_counters.delta.queue_overflow,
                 .nfqueue_runtime_counters.delta.attribution_timeout,
                 .nfqueue_runtime_counters.delta.terminal_queue_error
             ] | all(.[]; type == "number" and . == 0))
             and (.nfqueue_runtime_counters.delta.denied
                  | type == "number" and . == 0)
             end)
        and (.identity_probe == null or .identity_probe.fail_open == false))
    and all(.results[];
        . as $result
        | any($report.backends[];
              .name == $result.backend
              and (
                  .status == "passed"
                  or ($allow_unsupported_iptables
                      and .name == "iptables"
                      and .status == "unsupported"
                      and $result.policy == "baseline")
              )))
    and all(.backends[];
        . as $backend
        | if .status == "passed"
          then any($report.results[];
                   .backend == $backend.name and .phase_role == "steady")
               and any($report.results[];
                       .backend == $backend.name and .phase_role == "burst")
          else true
          end)
' "$report_json" >/dev/null \
    || fail 'report.json does not satisfy the release performance gate'

if ! python3 -I -B -S - "$config" "$report_json" "$repository_root" <<'PY'
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
report = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
repository = Path(sys.argv[3])
status_by_backend = {
    backend["name"]: backend["status"] for backend in report["backends"]
}

harness_paths = (
    "tests/perf/ci-smoke.sh",
    "tests/perf/control.py",
    "tests/perf/environment.py",
    "tests/perf/metrics.py",
    "tests/perf/run.py",
    "tests/perf/runtime_launcher.py",
    "tests/perf/workloads/common.py",
    "tests/perf/workloads/identity_probe.c",
    "tests/perf/workloads/tcp.py",
    "tests/perf/workloads/udp.py",
)
harness_components = report["harness"]["components"]
if [component.get("path") for component in harness_components] != list(harness_paths):
    print("performance CI smoke: harness component plan mismatch", file=sys.stderr)
    raise SystemExit(1)
harness_manifest = hashlib.sha256()
for relative, component in zip(harness_paths, harness_components, strict=True):
    path = repository / relative
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        print(
            f"performance CI smoke: cannot open harness component {relative}: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    payload_chunks = []
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > 4 * 1024 * 1024
        ):
            print(
                f"performance CI smoke: unsafe harness component: {relative}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        observed = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            observed += len(chunk)
            if observed > 4 * 1024 * 1024:
                print(
                    f"performance CI smoke: oversized harness component: {relative}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            payload_chunks.append(chunk)
        metadata_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
        != (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
        )
    ):
        print(f"performance CI smoke: harness component changed: {relative}", file=sys.stderr)
        raise SystemExit(1)
    payload = b"".join(payload_chunks)
    digest = hashlib.sha256(payload).hexdigest()
    if len(payload) != metadata.st_size or component != {
        "path": relative,
        "size": len(payload),
        "sha256": digest,
    }:
        print(f"performance CI smoke: harness component digest mismatch: {relative}", file=sys.stderr)
        raise SystemExit(1)
    harness_manifest.update(relative.encode("ascii"))
    harness_manifest.update(b"\0")
    harness_manifest.update(str(len(payload)).encode("ascii"))
    harness_manifest.update(b"\0")
    harness_manifest.update(digest.encode("ascii"))
    harness_manifest.update(b"\n")
if harness_manifest.hexdigest() != report["harness"]["manifest_sha256"]:
    print("performance CI smoke: harness manifest digest mismatch", file=sys.stderr)
    raise SystemExit(1)

runtime_plan = (
    ("tests/perf/runtime_launcher.py", "runtime_launcher.py"),
    ("tests/perf/control.py", "control.py"),
    ("tests/perf/metrics.py", "metrics.py"),
    ("tests/perf/workloads/common.py", "workloads/common.py"),
    ("tests/perf/workloads/identity_probe.c", "workloads/identity_probe.c"),
    ("tests/perf/workloads/tcp.py", "workloads/tcp.py"),
    ("tests/perf/workloads/udp.py", "workloads/udp.py"),
)
runtime = report["harness"].get("runtime_bundle")
if not isinstance(runtime, dict) or (
    runtime.get("schema") != "openshield.perf.runtime-bundle.v1"
    or runtime.get("container_root") != "/opt/openshield-perf"
    or runtime.get("python_flags") != ["-I", "-B", "-S"]
    or runtime.get("source_only") is not True
    or runtime.get("entrypoints")
    != ["control.py", "metrics.py", "workloads/tcp.py", "workloads/udp.py"]
    or runtime.get("manifest_path") != ".manifest.json"
):
    print("performance CI smoke: runtime bundle policy mismatch", file=sys.stderr)
    raise SystemExit(1)
runtime_components = runtime.get("components")
if (
    not isinstance(runtime_components, list)
    or [
        (component.get("source_path"), component.get("path"))
        if isinstance(component, dict)
        else None
        for component in runtime_components
    ]
    != list(runtime_plan)
):
    print("performance CI smoke: runtime bundle component plan mismatch", file=sys.stderr)
    raise SystemExit(1)
harness_by_path = {component["path"]: component for component in harness_components}
for (source_relative, runtime_relative), component in zip(
    runtime_plan, runtime_components, strict=True
):
    expected = harness_by_path[source_relative]
    if component != {
        "path": runtime_relative,
        "source_path": source_relative,
        "size": expected["size"],
        "sha256": expected["sha256"],
    }:
        print(
            f"performance CI smoke: runtime component evidence mismatch: {runtime_relative}",
            file=sys.stderr,
        )
        raise SystemExit(1)
runtime_manifest_document = {
    key: runtime[key]
    for key in (
        "schema",
        "container_root",
        "python_flags",
        "source_only",
        "entrypoints",
        "components",
    )
}
runtime_manifest_payload = json.dumps(
    runtime_manifest_document,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode("utf-8")
if hashlib.sha256(runtime_manifest_payload).hexdigest() != runtime.get(
    "manifest_sha256"
):
    print("performance CI smoke: runtime manifest evidence mismatch", file=sys.stderr)
    raise SystemExit(1)
runtime_root = Path(sys.argv[2]).parent / "runtime-bundle"
expected_runtime_files = {path for _, path in runtime_plan} | {".manifest.json"}
observed_runtime_files = set()
observed_runtime_directories = set()
if runtime_root.is_symlink() or not runtime_root.is_dir():
    print("performance CI smoke: runtime bundle directory is unavailable", file=sys.stderr)
    raise SystemExit(1)
for current, directories, files in os.walk(runtime_root, followlinks=False):
    current_path = Path(current)
    relative_directory = current_path.relative_to(runtime_root).as_posix()
    observed_runtime_directories.add(
        "" if relative_directory == "." else relative_directory
    )
    for name in directories:
        target = current_path / name
        metadata = target.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
            print("performance CI smoke: unsafe runtime directory", file=sys.stderr)
            raise SystemExit(1)
    for name in files:
        target = current_path / name
        metadata = target.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
            print("performance CI smoke: unsafe runtime file", file=sys.stderr)
            raise SystemExit(1)
        observed_runtime_files.add(target.relative_to(runtime_root).as_posix())
if observed_runtime_directories != {"", "workloads"} or observed_runtime_files != expected_runtime_files:
    print("performance CI smoke: runtime bundle has missing or extra entries", file=sys.stderr)
    raise SystemExit(1)
if (runtime_root / ".manifest.json").read_bytes() != runtime_manifest_payload:
    print("performance CI smoke: staged runtime manifest mismatch", file=sys.stderr)
    raise SystemExit(1)
for component in runtime_components:
    payload = (runtime_root / component["path"]).read_bytes()
    if len(payload) != component["size"] or hashlib.sha256(payload).hexdigest() != component["sha256"]:
        print(
            f"performance CI smoke: staged runtime component mismatch: {component['path']}",
            file=sys.stderr,
        )
        raise SystemExit(1)

ordinary_rpm_record = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9+._-]*\|[0-9]+\|"
    r"[A-Za-z0-9][A-Za-z0-9+._~^-]*\|"
    r"[A-Za-z0-9][A-Za-z0-9+._~^-]*\|"
    r"[A-Za-z0-9][A-Za-z0-9_+-]*\Z"
)
signing_key_record = re.compile(
    r"gpg-pubkey\|[0-9]+\|"
    r"[A-Za-z0-9][A-Za-z0-9+._~^-]*\|"
    r"[A-Za-z0-9][A-Za-z0-9+._~^-]*\|\(none\)\Z"
)
for environment in report["environments"]:
    records = environment["rpm_nevra"]
    if records != sorted(set(records)) or not all(
        isinstance(record, str)
        and (
            ordinary_rpm_record.fullmatch(record)
            or signing_key_record.fullmatch(record)
        )
        for record in records
    ):
        print("performance CI smoke: RPM inventory is not canonical", file=sys.stderr)
        raise SystemExit(1)
    manifest = ("\n".join(records) + "\n").encode("ascii")
    if hashlib.sha256(manifest).hexdigest() != environment["rpm_manifest_sha256"]:
        print("performance CI smoke: RPM inventory digest mismatch", file=sys.stderr)
        raise SystemExit(1)

phases = [("warmup", "warmup", config["phases"]["warmup"]["scale"], None)]
phases.extend(
    (f"ramp_{index}", "ramp", scale, None)
    for index, scale in enumerate(config["phases"]["ramp"]["scales"], 1)
)
phases.extend(
    (f"steady_{repetition}", "steady", 1.0, repetition)
    for repetition in range(1, config["phases"]["steady"]["repetitions"] + 1)
)
phases.append(("burst", "burst", config["phases"]["burst"]["scale"], None))


def scenarios(profile, policies):
    for policy in policies:
        if policy == "baseline":
            yield policy, None, None
        elif policy == "network_only":
            for mode in config["modes"]:
                yield policy, mode, None
        else:
            yield policy, "enforcing", None
            for variant in config["learning_variants"]:
                yield policy, "learning", variant


key_fields = (
    "backend",
    "policy",
    "mode",
    "learning_variant",
    "profile",
    "direction",
    "transport",
    "load_level",
    "phase",
    "phase_role",
    "phase_scale",
    "repetition",
)
expected = Counter()
for backend in config["backends"]:
    unsupported = status_by_backend[backend] == "unsupported"
    for profile in config["profiles"]:
        policies = ["baseline"] if unsupported else profile["policy_cases"]
        for policy, mode, variant in scenarios(profile, policies):
            for load_level in config["load_levels"]:
                for phase, role, scale, repetition in phases:
                    expected[
                        (
                            backend,
                            policy,
                            mode,
                            variant,
                            profile["name"],
                            profile["direction"],
                            profile["transport"],
                            load_level,
                            phase,
                            role,
                            scale,
                            repetition,
                        )
                    ] += 1

try:
    actual = Counter(tuple(result[field] for field in key_fields) for result in report["results"])
except (KeyError, TypeError) as error:
    print(f"performance CI smoke: incomplete result identity: {error}", file=sys.stderr)
    raise SystemExit(1)

if actual != expected:
    missing = list((expected - actual).elements())[:5]
    unexpected = list((actual - expected).elements())[:5]
    print(
        "performance CI smoke: result plan mismatch: "
        f"expected={sum(expected.values())}, actual={sum(actual.values())}, "
        f"missing={sum((expected - actual).values())}, "
        f"unexpected={sum((actual - expected).values())}",
        file=sys.stderr,
    )
    for item in missing:
        print(f"performance CI smoke: missing result key: {item!r}", file=sys.stderr)
    for item in unexpected:
        print(f"performance CI smoke: unexpected result key: {item!r}", file=sys.stderr)
    raise SystemExit(1)

if config.get("overload", {}).get("enabled"):
    expected_overload = {
        (backend, transport)
        for backend, status in status_by_backend.items()
        if status == "passed"
        for transport in ("tcp", "udp")
    }
    try:
        actual_overload = {
            (result["backend"], result["transport"])
            for result in report["overload_results"]
        }
    except (KeyError, TypeError) as error:
        print(f"performance CI smoke: malformed overload identity: {error}", file=sys.stderr)
        raise SystemExit(1)
    if actual_overload != expected_overload or len(report["overload_results"]) != len(expected_overload):
        print(
            "performance CI smoke: controlled overload plan mismatch: "
            f"expected={sorted(expected_overload)!r}, actual={sorted(actual_overload)!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)
PY
then
    fail 'report.json does not cover the exact configured result plan'
fi

readonly EXPECTED_CSV_HEADER='backend,policy,mode,learning_variant,profile,direction,transport,load_level,phase,phase_role,phase_scale,valid,passed,safety_pass,capacity_pass,relative_performance_pass,unreliable_reasons,failure_reasons,safety_failure_reasons,relative_performance_failure_reasons,target_ops_per_second,actual_application_ops_per_second,actual_application_mbps,target_attainment_ratio,actual_cps,active_flows_peak,latency_p50_ms,latency_p95_ms,latency_p99_ms,connect_latency_p50_ms,connect_latency_p95_ms,connect_latency_p99_ms,error_ratio,udp_reply_loss_ratio,udp_scenario_accounting_valid,udp_scenario_packets_sent,udp_scenario_packets_received,udp_scenario_packet_loss,udp_scenario_packet_loss_ratio,udp_scenario_unexpected_packets,udp_scenario_packet_matched,udp_barriers_expected,udp_barriers_sent,udp_server_barriers_received,udp_server_barrier_acks_sent,udp_barrier_acks_received,udp_barrier_errors,udp_barriers_matched,tcp_retransmits,tcp_retransmits_per_tx_packet,dut_rx_pps,dut_tx_pps,dut_rx_mbps,dut_tx_mbps,aggregate_dut_pps,daemon_cpu_percent_one_core,cgroup_cpu_percent_one_core,daemon_rss_bytes_peak,softirq_net_rx,softirq_net_tx,conntrack_count_peak,nfqueue_hits,nfqueue_depth_peak,nfqueue_kernel_dropped,nfqueue_user_dropped,nfqueue_runtime_counters_valid,nfqueue_queue_overflow_delta,nfqueue_attribution_timeout_delta,nfqueue_terminal_queue_error_delta,nfqueue_denied_delta,nfqueue_hits_per_connection,nfqueue_hits_per_datagram,identity_probe_fail_open,quarantine_occurred,application_ops_reduction_percent,throughput_reduction_percent,aggregate_dut_pps_reduction_percent,latency_p50_increase_percent,latency_p95_increase_percent,latency_p99_increase_percent,connect_latency_p50_increase_percent,connect_latency_p95_increase_percent,connect_latency_p99_increase_percent,cgroup_cpu_increase_percent'
IFS= read -r csv_header < "$report_csv" \
    || fail 'report.csv does not contain a header'
csv_header=${csv_header%$'\r'}
[[ "$csv_header" == "$EXPECTED_CSV_HEADER" ]] \
    || fail 'report.csv does not contain the expected schema header'
json_result_count=$(jq -r '.results | length' "$report_json")
csv_line_count=$(awk 'END { print NR }' "$report_csv")
(( csv_line_count == json_result_count + 1 )) \
    || fail 'report.csv row count does not match report.json'

readonly EXPECTED_OVERLOAD_CSV_HEADER='backend,policy,mode,profile,canary_profile,transport,probe_transport,valid,passed,safety_pass,recovery_pass,pressure_start_gate_ready,resource_valid,allowed_preflight_pass,network_liveness_preflight_pass,wrong_executable_preflight_blocked,saturation_proven,stall_kernel_drops,stall_user_drops,stall_total_drops,timestamps_ordered,during_stall_blocked_all,during_stall_fail_open,during_stall_liveness_pass,after_resume_blocked,after_resume_liveness_pass,quarantine_reported,quarantine_occurred,kernel_block_all,quarantine_black_box_pass,validity_failure_reasons,safety_failure_reasons,recovery_failure_reasons'
IFS= read -r overload_csv_header < "$overload_csv" \
    || fail 'overload.csv does not contain a header'
overload_csv_header=${overload_csv_header%$'\r'}
[[ "$overload_csv_header" == "$EXPECTED_OVERLOAD_CSV_HEADER" ]] \
    || fail 'overload.csv does not contain the expected schema header'
json_overload_count=$(jq -r '.overload_results | length' "$report_json")
overload_csv_line_count=$(awk 'END { print NR }' "$overload_csv")
(( overload_csv_line_count == json_overload_count + 1 )) \
    || fail 'overload.csv row count does not match report.json'

IFS= read -r markdown_title < "$report_markdown" \
    || fail 'report.md does not contain a title'
[[ "$markdown_title" == '# OpenShield performance report' ]] \
    || fail 'report.md does not contain the expected title'
grep -Fqx 'Overall result: **PASS**' "$report_markdown" \
    || fail 'report.md does not record a passing result'

printf 'performance CI smoke: PASS (%s)\n' "$output_directory"
