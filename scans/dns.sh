#!/usr/bin/env bash

source "lib/colors.sh"

run_dns_scan() {
    local output_dir=$1
    echo -e "${YELLOW}Starting DNS Vulnerabilities scan using 'dig +dnssec'.${NC}\n"

    if [[ -f "$output_dir/nmap/DNS.gnmap" ]]; then
        local ips_with_port_53_open=$(awk '/^Host: / && /Ports:.*53\/open/{print $2}' "$output_dir/nmap/DNS.gnmap")

        if [[ -n "$ips_with_port_53_open" ]]; then
            mkdir -p "$output_dir/dnssec"
            for ip in $ips_with_port_53_open; do
                echo -e "\n${GREEN}Running 'dig +dnssec' on $ip${NC}"

                dig_output=$(dig +dnssec "$ip")

                if echo "$dig_output" | grep -q " flags:.*ra"; then
                    echo "$dig_output" | tee "$output_dir/dnssec/${ip}_recursion_test.txt"
                    echo -e "${BLUE}DNS Recursion vulnerability found for $ip.${NC}"
                elif ! echo "$dig_output" | grep -q " flags:.*ad"; then
                    echo "$dig_output" | tee "$output_dir/dnssec/${ip}_dns_dnssec_test.txt"
                    echo -e "${BLUE}DNSSec not configured vulnerability found for $ip.${NC}"
                else
                    echo "$dig_output" | tee "$output_dir/dnssec/${ip}_dnssec_scan.txt"
                    echo -e "${BLUE}No DNS vulnerabilities found for $ip.${NC}\n"
                fi
                echo -e "\n--------------------------------\n"
            done
        else
            echo -e "${YELLOW}No hosts with port 53 open. Skipping DNSSec scan.${NC}\n"
        fi
    else
        echo -e "${RED}DNS.gnmap not found. Skipping DNSSec scan.${NC}\n"
    fi
    echo -e "${BLUE}DNS Vulnerabilities Scan Completed.${NC}\n"
}
