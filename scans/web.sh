#!/usr/bin/env bash

# scans/web.sh
# Handles SSLScan and SSH-Audit for open ports 443 and 22.

source "lib/colors.sh"

run_sslscan() {
    local target=$1
    local output_dir=$2
    local output_file="$output_dir/sslscan/${target}_sslscan.txt"
    mkdir -p "$(dirname "$output_file")"
    echo -e "${GREEN}Starting SSLScan on $target${NC}"
    sslscan --verbose "$target" | tee "$output_file"
    echo -e "${GREEN}SSLScan on $target completed.${NC}"
    echo -e "\n--------------------------------\n"
}

run_ssh_audit() {
    local target=$1
    local output_dir=$2
    local output_file="$output_dir/sshaudit/${target}_sshaudit.txt"
    mkdir -p "$(dirname "$output_file")"
    echo -e "${GREEN}Starting SSH-Audit on $target${NC}"
    ssh-audit -v "$target" | tee "$output_file"
    echo -e "${GREEN}SSH-Audit on $target completed.${NC}"
    echo -e "\n--------------------------------\n"
}

run_web_scans() {
    local output_dir="$1"

    echo -e "${YELLOW}Starting SSLScan and SSH-Audit.${NC}\n"

    # Get a list of targets with port 443 open from the Nmap SSLCipher scan
    if [[ -f "$output_dir/nmap/SSLCipher.gnmap" ]]; then
        local ssl_targets=$(awk '/Host: / && /Ports:.*443\/open/ {print $2}' "$output_dir/nmap/SSLCipher.gnmap")
        if [[ -n "$ssl_targets" ]]; then
            echo -e "${GREEN}Found targets with port 443 open. Starting SSLScan...${NC}"
            for target in $ssl_targets; do
                run_sslscan "$target" "$output_dir" &
            done
        else
            echo -e "${YELLOW}No targets with port 443 open found. Skipping SSLScan.${NC}\n"
        fi
    else
        echo -e "${RED}Nmap SSLCipher scan result not found. Skipping SSLScan.${NC}\n"
    fi

    # Get a list of targets with port 22 open from the Nmap SSH scan
    if [[ -f "$output_dir/nmap/SSH.gnmap" ]]; then
        local ssh_targets=$(awk '/Host: / && /Ports:.*22\/open/ {print $2}' "$output_dir/nmap/SSH.gnmap")
        if [[ -n "$ssh_targets" ]]; then
            echo -e "${GREEN}Found targets with port 22 open. Starting SSH-Audit...${NC}"
            for target in $ssh_targets; do
                run_ssh_audit "$target" "$output_dir" &
            done
        else
            echo -e "${YELLOW}No targets with port 22 open found. Skipping SSH-Audit.${NC}\n"
        fi
    else
        echo -e "${RED}Nmap SSH scan result not found. Skipping SSH-Audit.${NC}\n"
    fi

    wait
    echo -e "${BLUE}SSLScan and SSH-Audit scans completed.${NC}\n"
}