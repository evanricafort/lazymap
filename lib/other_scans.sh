#!/bin/bash
# Functions for running additional scans like sslscan, ssh-audit, and checkheaders

run_sslscan() {
    local target=$1
    local output_file="results/sslscan/${target}_sslscan.txt"
    mkdir -p "$(dirname "$output_file")"
    echo -e "${GREEN}Starting SSLScan on $target${NC}"
    sslscan --verbose "$target" | tee "$output_file"
    echo -e "${GREEN}SSLScan results saved to $output_file${NC}"
    echo -e "${GREEN}SSLScan on $target completed.${NC}"
    echo -e "\n--------------------------------\n"
}

run_ssh_audit() {
    local target=$1
    local output_file="results/sshaudit/${target}_sshaudit.txt"
    mkdir -p "$(dirname "$output_file")"
    echo -e "${GREEN}Starting SSH-Audit on $target${NC}"
    ssh-audit -v "$target" | tee "$output_file"
    echo -e "${GREEN}SSH-audit results saved to $output_file${NC}"
    echo -e "${GREEN}SSH-Audit on $target completed.${NC}"
    echo -e "\n--------------------------------\n"
}

get_open_ports() {
    local host=$1
    local ports=$(nmap -Pn -p 80,443,8080,8443 --host-timeout 5s --max-retries 0 "$host" | awk '/^[0-9]+\/tcp/ && /open/ {split($1,a,"/"); print a[1]}')
    echo "$ports"
}

check_single_header() {
    local header=$1
    local headers=$2
    local url=$3
    local log_file=$4
    if echo "$headers" | grep -i "$header:" > /dev/null; then
        echo -e "${GREEN}${header} header found${NC}"
        echo "$url: ${header} header found" >> "$log_file"
    else
        echo -e "${RED}${header} header missing${NC}"
        echo "$url: ${header} header missing" >> "$log_file"
    fi
}

check_headers() {
    local url=$1
    echo -e "${GREEN}Starting CheckThatHeaders on $url${NC}"
    local open_ports=$(get_open_ports "$url")
    if [[ -z "$open_ports" ]]; then
        echo -e "${RED}No open ports found on $url. Skipping header checks.${NC}"
        echo -e "\n--------------------------------\n"
        return
    fi
    for port in $open_ports; do
        local log_file="results/checkthatheader/${url}_${port}_header_check.txt"
        mkdir -p "$(dirname "$log_file")"
        echo -e "${GREEN}Fetching headers from $url:$port${NC}"
        headers=$(wget -d --verbose --spider --server-response --timeout=10 --tries=1 "$url:$port" 2>&1 | tee "$log_file" | grep -i -E "Content-Security-Policy|Permissions-Policy|Referrer-Policy|X-Content-Type-Options|Strict-Transport-Security|X-Frame-Options")
        check_single_header "Content-Security-Policy" "$headers" "$url:$port" "$log_file"
        check_single_header "Permissions-Policy" "$headers" "$url:$port" "$log_file"
        check_single_header "Referrer-Policy" "$headers" "$url:$port" "$log_file"
        check_single_header "X-Content-Type-Options" "$headers" "$url:$port" "$log_file"
        check_single_header "Strict-Transport-Security" "$headers" "$url:$port" "$log_file"
        check_single_header "X-Frame-Options" "$headers" "$url:$port" "$log_file"
    done
    echo -e "${GREEN}Header checks for $url completed. Check the 'checkthatheader' folder for the output.${NC}"
    echo -e "\n--------------------------------\n"
}

scan_target() {
    local target=$1
    if is_subnet "$target"; then
        relay_from_tcp_scan "$target"
        if [[ -f "results/live_hosts.txt" ]]; then
            cat results/live_hosts.txt >> results/all_targets.txt
            while IFS= read -r live_host; do
                if [[ "$exclude_sslscan" != true ]]; then run_sslscan "$live_host"; fi
                if [[ "$exclude_sshaudit" != true ]]; then run_ssh_audit "$live_host"; fi
                if [[ "$exclude_checkheaders" != true ]]; then check_headers "$live_host"; fi
            done < results/live_hosts.txt
            rm results/live_hosts.txt
        fi
    else
        echo "$target" >> results/all_targets.txt
        if [[ "$exclude_sslscan" != true ]]; then run_sslscan "$target"; fi
        if [[ "$exclude_sshaudit" != true ]]; then run_ssh_audit "$target"; fi
        if [[ "$exclude_checkheaders" != true ]]; then check_headers "$target"; fi
    fi
}

run_other_scans() {
    local targets_file=$1
    local single_target=$2
    if [[ "$exclude_sslscan" != true || "$exclude_sshaudit" != true || "$exclude_checkheaders" != true ]]; then
        echo -e "${YELLOW}Starting SSLScan, SSH-Audit, and CheckThatHeaders.${NC}\n"
    fi
    if [[ -n "$targets_file" ]]; then
        while IFS= read -r target; do
            scan_target "$target"
        done < "$targets_file"
    elif [[ -n "$single_target" ]]; then
        scan_target "$single_target"
    fi
    if [[ "$exclude_sslscan" != true ]]; then
        echo -e "${BLUE}SSLScan, SSH-Audit, and CheckThatHeaders scans completed.${NC}"
        echo -e "\n--------------------------------\n"
        echo -e "\n"
    fi
}

relay_from_tcp_scan() {
    local subnet=$1
    echo -e "\n${YELLOW}Target is a subnet, starting the live hosts check.${NC}\n"
    echo -e "${GREEN}Running Nmap to get live hosts in subnet $subnet${NC}"
    nmap -sn "$subnet" -oG - | awk '/Up$/{print $2}' > results/live_hosts.txt
    echo -e "Found live hosts in $subnet:"
    cat results/live_hosts.txt
    echo -e "\n${BLUE}Live hosts check completed.${NC}\n"
}