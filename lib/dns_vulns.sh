#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check for DNS vulnerabilities
run_dns_vulns_scan() {
    echo -e "\n--------------------------------\n"
    echo -e "${YELLOW}Starting DNS Vulnerabilities scan using 'dig +dnssec'.${NC}\n"

    if [[ -f "results/dnsvuln.gnmap" ]]; then
        ips_with_port_53_open=$(awk '/^Host: / && /Ports:.*53\/open/{print $2}' results/dnsvuln.gnmap)
        
        if [[ -n "$ips_with_port_53_open" ]]; then
            echo -e "${YELLOW}Port 53 found open on the following hosts:${NC}"
            echo "$ips_with_port_53_open"
            mkdir -p results/dnssec

            for ip in $ips_with_port_53_open; do
                echo -e "\n${GREEN}Running 'dig +dnssec' on $ip${NC}"
                
                # Check for DNS Recursion Vulnerability (ra flag)
                dig_recursion_output=$(dig +short +norecurse @$ip google.com)
                if [[ -z "$dig_recursion_output" ]]; then
                    output_file="results/dnssec/${ip}_recursion_test.txt"
                    dig +short +norecurse @$ip google.com > "$output_file"
                    echo -e "${BLUE}DNS Recursion vulnerability found for $ip. Output saved to $output_file${NC}"
                fi

                # Check for DNSSEC Misconfiguration (ad flag)
                dig_dnssec_output=$(dig +dnssec @$ip google.com)
                if ! echo "$dig_dnssec_output" | grep -q "flags:.*ad"; then
                    output_file="results/dnssec/${ip}_dnssec_test.txt"
                    echo "$dig_dnssec_output" | tee "$output_file"
                    echo -e "${BLUE}DNSSec not configured vulnerability found for $ip. Output saved to $output_file${NC}"
                fi

                # If no specific vulnerabilities were found, create a generic log
                if [[ -f "results/dnssec/${ip}_recursion_test.txt" ]] && [[ -f "results/dnssec/${ip}_dnssec_test.txt" ]]; then
                    : # Do nothing, vulnerabilities were found
                else
                    output_file="results/dnssec/${ip}_no_vulnerabilities_found.txt"
                    echo -e "${BLUE}No specific DNS vulnerabilities found for $ip. Raw dig output saved to $output_file${NC}"
                    dig +dnssec @$ip > "$output_file"
                fi
                
                echo -e "\n--------------------------------\n"
            done
        else
            echo -e "${YELLOW}No hosts found with port 53 open. Skipping DNSSec scan.${NC}"
        fi
    else
        echo -e "${RED}dnsvuln.gnmap not found. Skipping DNSSec scan.${NC}\n"
    fi
    echo -e "${BLUE}DNS Vulnerabilities Scan Completed.${NC}\n"
    echo -e "\n--------------------------------\n"
}
