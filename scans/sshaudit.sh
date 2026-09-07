#!/usr/bin/env bash

# scans/sshaudit.sh
# SSH server configuration audit with ssh-audit, against hosts found with 22
# open by the nmap SSH module.

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"

run_ssh_audit() {
    local target=$1
    local output_dir=$2
    local output_file="$output_dir/sshaudit/${target}_sshaudit.txt"
    mkdir -p "$(dirname "$output_file")"
    if step_completed "sshaudit:$target"; then
        skip_notice "sshaudit:$target" "SSH-Audit on $target"
        return 0
    fi
    echo -e "${GREEN}Starting SSH-Audit on $target${NC}"
    ssh-audit -v "$target" | tee "$output_file"
    mark_completed "sshaudit:$target"
    echo -e "${GREEN}SSH-Audit on $target completed.${NC}"
    echo -e "\n--------------------------------\n"
}

run_sshaudit_scans() {
    local output_dir="$1"

    echo -e "${YELLOW}Starting SSH-Audit.${NC}\n"
    activity_begin "sshaudit"

    if [[ -f "$output_dir/nmap/SSH.gnmap" ]]; then
        local ssh_targets
        ssh_targets=$(awk '/Host: / && /Ports:.*22\/open\// {print $2}' "$output_dir/nmap/SSH.gnmap")
        if [[ -n "$ssh_targets" ]]; then
            echo -e "${GREEN}Found targets with port 22 open. Starting SSH-Audit...${NC}"
            local target
            for target in $ssh_targets; do
                run_ssh_audit "$target" "$output_dir" &
            done
            # Targets run in parallel; wait for them all before moving on.
            wait
        else
            echo -e "${YELLOW}No targets with port 22 open found. Skipping SSH-Audit.${NC}\n"
        fi
    else
        echo -e "${RED}Nmap SSH scan result not found. Skipping SSH-Audit.${NC}\n"
    fi

    activity_end
    echo -e "${BLUE}SSH-Audit Completed.${NC}\n"
}
