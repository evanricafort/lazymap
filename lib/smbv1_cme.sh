#!/bin/bash

# Function to perform CrackMapExec SMBv1 scan
run_cme_smbv1() {
    echo -e "\n--------------------------------\n"
    echo -e "${YELLOW}Starting CrackMapExec for SMBv1 detection.${NC}\n"

    local target_list=""
    if [[ -n "$targets_file" ]]; then
        target_list="$targets_file"
    elif [[ -n "$single_target" ]]; then
        target_list="$single_target"
    else
        echo -e "${RED}No valid target specified for CrackMapExec.${NC}"
        target_list=""
    fi

    if [[ -n "$target_list" ]]; then
        crackmapexec smb -p 445 "$target_list" | grep SMBv1:True > results/smbv1.txt
        if [[ -s "results/smbv1.txt" ]]; then
            echo -e "${GREEN}CrackMapExec found SMBv1 enabled on the following IPs:${NC}"
            cat results/smbv1.txt
        else
            echo -e "${RED}No SMBv1 enabled hosts found.${NC}\n"
        fi
        echo -e "${BLUE}CrackMapExec SMBv1 detection completed.${NC}"
    else
        echo -e "${RED}No targets provided for CrackMapExec. Skipping SMBv1 detection.${NC}"
    fi
    echo -e "\n--------------------------------\n"
}
