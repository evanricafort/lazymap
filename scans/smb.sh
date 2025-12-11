#!/usr/bin/env bash

source "lib/colors.sh"

run_smb_scans() {
    local output_dir="$1"
    shift
    local targets_array=("$@")

    echo -e "${YELLOW}Starting CrackMapExec for SMBv1 detection.${NC}\n"
    local target_list=""
    if [[ "${#targets_array[@]}" -gt 0 ]]; then
        target_list="${targets_array[*]}"
    fi

    if [[ -n "$target_list" ]]; then
        crackmapexec smb -p 445 "$target_list" | grep SMBv1:True > "$output_dir/smbv1.txt"
        if [[ -s "$output_dir/smbv1.txt" ]]; then
            echo -e "${GREEN}CrackMapExec found SMBv1 enabled.${NC}"
        else
            echo -e "${RED}No SMBv1 enabled hosts found.${NC}\n"
        fi
    else
        echo -e "${RED}No targets provided for CrackMapExec. Skipping.${NC}"
    fi

    echo -e "${BLUE}CrackMapExec SMBv1 detection completed.${NC}\n"

    if [[ -s "$output_dir/rpc_targets.txt" ]]; then
        echo -e "${YELLOW}Starting Unauthenticated RPC scan.${NC}\n"
        mkdir -p "$output_dir/unauthrpc"
        while IFS= read -r target_ip; do
            echo -e "${GREEN}Attempting Unauthenticated RPC connection to $target_ip${NC}"
            rpcclient -U "" -N "$target_ip" -c 'enumprivs' 2>&1 | tee "$output_dir/unauthrpc/${target_ip}.txt"
            if grep -q -E "Cannot connect|NT_STATUS|failed|Connection to host failed" "$output_dir/unauthrpc/${target_ip}.txt"; then
                echo -e "${RED}Connection to $target_ip failed.${NC}"
            else
                echo -e "${BLUE}Unauthenticated RPC connection to $target_ip successful.${NC}"
            fi
        done < "$output_dir/rpc_targets.txt"
        echo -e "${BLUE}Unauthenticated RPC scan completed.${NC}\n"
    else
        echo -e "${YELLOW}No RPC targets found. Skipping Unauthenticated RPC scan.${NC}\n"
    fi
}
