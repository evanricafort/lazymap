#!/bin/bash

# Function to perform unauthenticated RPC scans
run_rpc_unauth_scan() {
    echo -e "\n--------------------------------\n"
    echo -e "${YELLOW}Starting Unauthenticated RPC scan.${NC}\n"

    # Extract RPC targets (port 135) from rpc.gnmap
    if [[ -f "results/rpc.gnmap" ]]; then
        awk '/^Host: / && /Ports:.*135\/open/ {print $2}' results/rpc.gnmap > results/rpc_targets.txt
    else
        echo -e "\n${RED}rpc.gnmap not found. Skipping RPC target extraction.${NC}"
        touch results/rpc_targets.txt
    fi

    if [[ -s "results/rpc_targets.txt" ]]; then
        mkdir -p results/unauthrpc
        while IFS= read -r target_ip; do
            echo -e "${GREEN}Attempting Unauthenticated RPC connection to $target_ip${NC}"
            output_file="results/unauthrpc/unauthrpc_${target_ip}.txt"
            rpcclient -U "" -N "$target_ip" -c 'enumprivs' 2>&1 | tee "$output_file"
            if grep -q -E "Cannot connect|NT_STATUS|failed|Connection to host failed" "$output_file"; then
                echo -e "${RED}Connection to $target_ip failed or authentication required. Skipping scan.${NC}"
                rm "$output_file"
            else
                echo -e "${BLUE}Unauthenticated RPC connection to $target_ip successful. Output saved to $output_file${NC}"
            fi
        done < results/rpc_targets.txt
        echo -e "\n${BLUE}Unauthenticated RPC scan completed.${NC}"
    else
        echo -e "${YELLOW}No RPC targets found. Skipping Unauthenticated RPC scan.${NC}"
    fi
    echo -e "\n--------------------------------\n"
}
