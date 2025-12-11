#!/usr/bin/env bash

run_live_host_check() {
    local output_dir=$1
    shift
    local targets_array=("$@")

    echo -e "${YELLOW}Starting live host check...${NC}\n"
    local temp_file="$output_dir/nmap/live_hosts_raw.txt"
    mkdir -p "$(dirname "$temp_file")"

    nmap -sn --disable-arp-ping -p 22,80,443,135,445 -n --max-retries=0 -T4 -v --reason -oN "$temp_file" "${targets_array[@]}"

    local live_hosts=()
    while read -r ip; do
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            live_hosts+=("$ip")
        fi
    done < <(grep "Nmap scan report for" "$temp_file" | awk '{print $NF}' | tr -d '()')

    rm "$temp_file"

    if [[ ${#live_hosts[@]} -eq 0 ]]; then
        echo -e "${RED}Error: No live hosts found from the provided targets.${NC}"
        exit 1
    fi

    echo -e "${GREEN}Found ${#live_hosts[@]} live hosts. Proceeding with scans...${NC}"

    printf "%s\n" "${live_hosts[@]}" > "$output_dir/live_hosts.txt"

    printf "%s\n" "${live_hosts[@]}"

    echo -e "${BLUE}Live host check completed.${NC}\n"
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

    if [[ "$needs_live_check" == true ]]; then
        mapfile -t TARGETS < <(run_live_host_check "$output_dir" "${TARGETS[@]}")
    fi
}
