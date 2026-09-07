#!/usr/bin/env bash

# scans/sslscan.sh
# SSL/TLS configuration and cipher review with sslscan, against hosts found
# with 443 open by the nmap SSLCipher module.

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"

run_sslscan() {
    local target=$1
    local output_dir=$2
    local output_file="$output_dir/sslscan/${target}_sslscan.txt"
    mkdir -p "$(dirname "$output_file")"
    if step_completed "sslscan:$target"; then
        skip_notice "sslscan:$target" "SSLScan on $target"
        return 0
    fi
    echo -e "${GREEN}Starting SSLScan on $target${NC}"
    sslscan --verbose "$target" | tee "$output_file"
    mark_completed "sslscan:$target"
    echo -e "${GREEN}SSLScan on $target completed.${NC}"
    echo -e "\n--------------------------------\n"
}

run_sslscan_scans() {
    local output_dir="$1"

    echo -e "${YELLOW}Starting SSLScan.${NC}\n"
    activity_begin "sslscan"

    if [[ -f "$output_dir/nmap/SSLCipher.gnmap" ]]; then
        local ssl_targets
        ssl_targets=$(awk '/Host: / && /Ports:.*443\/open\// {print $2}' "$output_dir/nmap/SSLCipher.gnmap")
        if [[ -n "$ssl_targets" ]]; then
            echo -e "${GREEN}Found targets with port 443 open. Starting SSLScan...${NC}"
            local target
            for target in $ssl_targets; do
                run_sslscan "$target" "$output_dir" &
            done
            # Targets run in parallel; wait for them all before moving on.
            wait
        else
            echo -e "${YELLOW}No targets with port 443 open found. Skipping SSLScan.${NC}\n"
        fi
    else
        echo -e "${RED}Nmap SSLCipher scan result not found. Skipping SSLScan.${NC}\n"
    fi

    activity_end
    echo -e "${BLUE}SSLScan Completed.${NC}\n"
}
