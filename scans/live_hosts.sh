#!/usr/bin/env bash

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"

# Discovers live hosts. Only the discovered IPs go to stdout - every status
# message and the nmap output go to stderr so the caller can safely capture
# the result without a pipeline subshell.
run_live_host_check() {
    local output_dir=$1
    shift
    local targets_array=("$@")

    echo -e "${YELLOW}Starting live host check...${NC}\n" >&2
    local temp_file="$output_dir/nmap/live_hosts_raw.txt"
    mkdir -p "$(dirname "$temp_file")"

    nmap -sn -v --reason -oN "$temp_file" "${targets_array[@]}" >&2

    local live_hosts=()
    while read -r ip; do
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            arr_push live_hosts "$ip"
        fi
    done < <(grep "Nmap scan report for" "$temp_file" | awk '{print $NF}' | tr -d '()')

    rm -f "$temp_file"

    if [[ ${#live_hosts[@]} -eq 0 ]]; then
        echo -e "${RED}Error: No live hosts found from the provided targets.${NC}" >&2
        return 1
    fi

    echo -e "${GREEN}Found ${#live_hosts[@]} live hosts. Proceeding with scans...${NC}" >&2

    printf "%s\n" "${live_hosts[@]}" > "$output_dir/live_hosts.txt"
    printf "%s\n" "${live_hosts[@]}"

    echo -e "${BLUE}Live host check completed.${NC}\n" >&2
}

run_live_host_scans() {
    local needs_live_check=false
    if [[ ${#TARGETS[@]} -gt 1 ]]; then
        needs_live_check=true
    else
        for target in "${TARGETS[@]}"; do
            if [[ "$target" == *"/"* ]]; then
                needs_live_check=true
                break
            fi
        done
    fi

    [[ "$needs_live_check" == true ]] || return 0

    # On resume, reuse the host list discovered by the interrupted run.
    if step_completed "live_hosts" && [[ -s "$output_dir/live_hosts.txt" ]]; then
        skip_notice "live_hosts" "live host discovery"
        read_lines_into TARGETS < "$output_dir/live_hosts.txt"
        echo -e "${GREEN}Reusing ${#TARGETS[@]} live host(s) from the previous run.${NC}\n"
        return 0
    fi

    read_lines_into TARGETS < <(run_live_host_check "$output_dir" "${TARGETS[@]}")

    if [[ ${#TARGETS[@]} -gt 0 ]]; then
        mark_completed "live_hosts"
    fi
}
