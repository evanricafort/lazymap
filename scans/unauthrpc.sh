#!/usr/bin/env bash

# scans/unauthrpc.sh
# Unauthenticated RPC (null session) enumeration using rpcclient.

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"
source "$LAZYMAP_DIR/lib/targets.sh"

run_unauth_rpc_scan() {
    local output_dir="$1"
    local targets="$output_dir/smb_targets.txt"

    echo -e "${YELLOW}Starting Unauthenticated RPC check using rpcclient.${NC}\n"

    # Built here as well as by the SMBv1 check, so this runs independently of
    # whether that check ran, was skipped, or was resumed past.
    if ! collect_smb_targets "$output_dir"; then
        echo -e "${RED}SMB nmap results not found. Skipping Unauthenticated RPC check.${NC}\n"
        echo -e "${BLUE}Unauthenticated RPC Check Completed.${NC}\n"
        return 0
    fi

    if [[ ! -s "$targets" ]]; then
        echo -e "${YELLOW}No SMB hosts available. Skipping Unauthenticated RPC check.${NC}\n"
        echo -e "${BLUE}Unauthenticated RPC Check Completed.${NC}\n"
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

    echo -e "${BLUE}Unauthenticated RPC Check Completed.${NC}\n"
}
