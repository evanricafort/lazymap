#!/usr/bin/env bash

# scans/smb.sh
# SMBv1 detection via crackmapexec and unauthenticated RPC enumeration via rpcclient.

source "$LAZYMAP_DIR/lib/colors.sh"

run_smbv1_scan() {
    local output_dir="$1"
    local smb_gnmap="$output_dir/nmap/SMB.gnmap"
    local smb_txt="$output_dir/nmap/SMB.txt"
    local targets="$output_dir/smb_targets.txt"

    echo -e "${YELLOW}Starting SMBv1 check using ${CME_BIN:-crackmapexec}.${NC}\n"

    if [[ -f "$smb_gnmap" ]]; then
        awk '/^Host: / && /Ports:.*(139|445)\/open/ {print $2}' "$smb_gnmap" | sort -u > "$targets"
    elif [[ -f "$smb_txt" ]]; then
        # Fall back to the normal-format output when no greppable file exists.
        awk '/Nmap scan report for/{ip=$NF; gsub(/[()]/,"",ip)} /^(139|445)\/tcp[[:space:]]+open/{print ip}' \
            "$smb_txt" | sort -u > "$targets"
    else
        echo -e "${RED}SMB nmap results not found. Skipping SMBv1 check.${NC}\n"
        return 0
    fi

    if [[ ! -s "$targets" ]]; then
        echo -e "${YELLOW}No hosts with port 139/445 open. Skipping SMBv1 check.${NC}\n"
        return 0
    fi

    "${CME_BIN:-crackmapexec}" smb "$targets" 2>&1 | tee "$output_dir/smbv1.txt"

    if grep -qi "SMBv1:True" "$output_dir/smbv1.txt" 2>/dev/null; then
        echo -e "${BLUE}SMBv1 enabled host(s) detected. See $output_dir/smbv1.txt${NC}\n"
    else
        echo -e "${BLUE}No SMBv1 enabled hosts detected.${NC}\n"
    fi
}

run_unauth_rpc_scan() {
    local output_dir="$1"
    local targets="$output_dir/smb_targets.txt"

    echo -e "${YELLOW}Starting Unauthenticated RPC check using rpcclient.${NC}\n"

    if [[ ! -s "$targets" ]]; then
        echo -e "${YELLOW}No SMB hosts available. Skipping Unauthenticated RPC check.${NC}\n"
        return 0
    fi

    mkdir -p "$output_dir/unauthrpc"

    while read -r ip; do
        [[ -z "$ip" ]] && continue
        echo -e "${GREEN}Running rpcclient null session against $ip${NC}"
        local out="$output_dir/unauthrpc/${ip}_rpcclient.txt"
        {
            echo "=== rpcclient -U \"\" -N $ip : srvinfo ==="
            rpcclient -U "" -N "$ip" -c "srvinfo" 2>&1
            echo
            echo "=== enumdomusers ==="
            rpcclient -U "" -N "$ip" -c "enumdomusers" 2>&1
            echo
            echo "=== enumdomgroups ==="
            rpcclient -U "" -N "$ip" -c "enumdomgroups" 2>&1
            echo
            echo "=== getdompwinfo ==="
            rpcclient -U "" -N "$ip" -c "getdompwinfo" 2>&1
        } | tee "$out"

        if grep -qiE "NT_STATUS_(ACCESS_DENIED|LOGON_FAILURE)" "$out"; then
            echo -e "${BLUE}Null session rejected on $ip.${NC}\n"
        else
            echo -e "${BLUE}Possible unauthenticated RPC access on $ip. See $out${NC}\n"
        fi
        echo -e "\n--------------------------------\n"
    done < "$targets"
}

run_smb_scans() {
    local output_dir="$1"

    run_step "smb:smbv1"     "SMBv1 check"              run_smbv1_scan     "$output_dir"
    run_step "smb:unauthrpc" "Unauthenticated RPC check" run_unauth_rpc_scan "$output_dir"

    echo -e "${BLUE}SMB and RPC Scans Completed.${NC}\n"
}
