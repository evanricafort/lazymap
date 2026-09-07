#!/usr/bin/env bash

# scans/pret.sh
# Printer security check using PRET (Credits to Jens Mueller).
# PRET is installed up front by lib/installer.sh when --pret is given; the
# install is retried here so the scan still works if that was skipped.

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"
source "$LAZYMAP_DIR/lib/installer.sh"

# Read-only PJL commands. PRET is interactive by default, so it is driven with
# a command file that ends in "exit" - otherwise an unattended scan would hang.
PRET_COMMANDS='id
info id
info status
info config
printenv
ls
exit'

run_pret_scan() {
    local output_dir=$1
    echo -e "${YELLOW}Starting PRET for Printer Security Check.${NC}\n"

    if ! pret_installed; then
        echo -e "${YELLOW}PRET is not set up yet. Installing it now...${NC}"
        if ! install_pret; then
            # Never abort here: the remaining scans and the HTML report still
            # have to be produced.
            echo -e "${RED}PRET is unavailable. Skipping the printer security check.${NC}\n"
            return 0
        fi
    fi

    local pret_script pret_py
    pret_script="$(pret_dir)/pret.py"
    pret_py="$(pret_python)"

    mkdir -p "$output_dir/pret"

    # Printers come from the nmap PJL scan (port 9100), the same way every
    # other module takes its targets from the nmap output.
    local targets="$output_dir/pret/printer_targets.txt"
    : > "$targets"
    if [[ -f "$output_dir/nmap/PJL.gnmap" ]]; then
        awk '/^Host: / && /Ports:.*9100\/open\// {print $2}' "$output_dir/nmap/PJL.gnmap" | sort -u > "$targets"
    fi

    if [[ ! -s "$targets" ]]; then
        echo -e "${YELLOW}No printers with port 9100 open were found.${NC}"
        echo -e "${GREEN}Falling back to PRET's local printer discovery.${NC}\n"
        local disc="$output_dir/pret/printer_discovery.txt"
        ( cd "$(pret_dir)" && "$pret_py" "$pret_script" ) > "$disc" 2>&1
        sed 's/^/  /' "$disc" | head -n 20
        echo -e "\n${BLUE}Printer discovery output saved to $disc.${NC}\n"
        echo -e "${BLUE}Printer security check completed.${NC}\n"
        return 0
    fi

    activity_begin "pret"
    local cmdfile="$output_dir/pret/pret_commands.txt"
    printf '%s\n' "$PRET_COMMANDS" > "$cmdfile"

    local ip
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        if step_completed "pret:$ip"; then
            skip_notice "pret:$ip" "PRET check on $ip"
            continue
        fi
        echo -e "${GREEN}Running PRET against printer $ip${NC}"
        local out="$output_dir/pret/pret_${ip}.txt"
        ( cd "$(pret_dir)" && "$pret_py" "$pret_script" "$ip" pjl -q -i "$cmdfile" ) > "$out" 2>&1
        mark_completed "pret:$ip"

        if grep -qiE 'Connection to .* failed|Connection refused' "$out"; then
            echo -e "${YELLOW}  Could not talk PJL to $ip.${NC}"
        else
            echo -e "${BLUE}  PRET output saved to $out${NC}"
        fi
        echo -e "\n--------------------------------\n"
    done < "$targets"

    activity_end
    echo -e "${BLUE}Printer security check completed.${NC}\n"
}
