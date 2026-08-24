#!/usr/bin/env bash

# scans/smbv1.sh
# SMBv1 detection using crackmapexec (or nxc).

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"
source "$LAZYMAP_DIR/lib/targets.sh"

run_smbv1_scan() {
    local output_dir="$1"
    local targets="$output_dir/smb_targets.txt"

    echo -e "${YELLOW}Starting SMBv1 check using ${CME_BIN:-crackmapexec}.${NC}\n"

    if ! collect_smb_targets "$output_dir"; then
        echo -e "${RED}SMB nmap results not found. Skipping SMBv1 check.${NC}\n"
        echo -e "${BLUE}SMBv1 Check Completed.${NC}\n"
        return 0
    fi

    if [[ ! -s "$targets" ]]; then
        echo -e "${YELLOW}No hosts with port 139/445 open. Skipping SMBv1 check.${NC}\n"
        echo -e "${BLUE}SMBv1 Check Completed.${NC}\n"
        return 0
    fi

    "${CME_BIN:-crackmapexec}" smb "$targets" 2>&1 | tee "$output_dir/smbv1.txt"

    if grep -qi "SMBv1:True" "$output_dir/smbv1.txt" 2>/dev/null; then
        echo -e "${BLUE}SMBv1 enabled host(s) detected. See $output_dir/smbv1.txt${NC}\n"
    else
        echo -e "${BLUE}No SMBv1 enabled hosts detected.${NC}\n"
    fi

    echo -e "${BLUE}SMBv1 Check Completed.${NC}\n"
}
