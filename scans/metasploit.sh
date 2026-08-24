#!/usr/bin/env bash

source "$LAZYMAP_DIR/lib/colors.sh"

run_metasploit_scan() {
    local resource_file=$1
    local output_file=$2
    echo "spool $output_file" >> "$resource_file"
    echo "run" >> "$resource_file"
    echo "spool off" >> "$resource_file"
    echo "exit" >> "$resource_file"
    msfconsole -q -r "$resource_file"
}

run_metasploit_scans() {
    local output_dir=$1

    if [[ -s "$output_dir/nmap/RDP.gnmap" ]]; then
        mkdir -p "$output_dir/msfrdp"
        awk '/^Host: / && /Ports:.*3389\/open/ {print $2}' "$output_dir/nmap/RDP.gnmap" > "$output_dir/rdp_targets.txt"
        if [[ -s "$output_dir/rdp_targets.txt" ]]; then
            echo -e "${GREEN}Starting RDP (Remote Desktop Protocol) scan.${NC}"
            while IFS= read -r target_ip; do
                if step_completed "msf:rdp:$target_ip"; then
                    skip_notice "msf:rdp:$target_ip" "RDP Metasploit scan on $target_ip"
                    continue
                fi
                local resource_script="$output_dir/msfrdp/rdp_scan_${target_ip}.rc"
                local output_file="$output_dir/msfrdp/rdp_${target_ip}.txt"
                echo "use auxiliary/scanner/rdp/rdp_scanner" > "$resource_script"
                echo "set RHOSTS $target_ip" >> "$resource_script"
                run_metasploit_scan "$resource_script" "$output_file"
                mark_completed "msf:rdp:$target_ip"
                echo -e "${BLUE}RDP scan for $target_ip completed, results saved to $output_file${NC}"
                echo
            done < "$output_dir/rdp_targets.txt"
        else
            echo -e "${YELLOW}No RDP targets found. Skipping RDP Metasploit scan.${NC}"
            echo
        fi
    fi

    if [[ -s "$output_dir/nmap/RPC.gnmap" ]]; then
        mkdir -p "$output_dir/msfrpc"
        awk '/^Host: / && /Ports:.*135\/open/ {print $2}' "$output_dir/nmap/RPC.gnmap" > "$output_dir/rpc_targets.txt"
        if [[ -s "$output_dir/rpc_targets.txt" ]]; then
            echo -e "${GREEN}Starting RPC (Remote Procedure Call) scan.${NC}"
            while IFS= read -r target_ip; do
                if step_completed "msf:rpc:$target_ip"; then
                    skip_notice "msf:rpc:$target_ip" "RPC Metasploit scan on $target_ip"
                    continue
                fi
                local resource_script="$output_dir/msfrpc/rpc_scan_${target_ip}.rc"
                local output_file="$output_dir/msfrpc/rpc_${target_ip}.txt"
                echo "use auxiliary/scanner/dcerpc/endpoint_mapper" > "$resource_script"
                echo "set RHOSTS $target_ip" >> "$resource_script"
                run_metasploit_scan "$resource_script" "$output_file"
                mark_completed "msf:rpc:$target_ip"
                echo -e "${BLUE}RPC scan for $target_ip completed, results saved to $output_file${NC}"
                echo
            done < "$output_dir/rpc_targets.txt"
        else
            echo -e "${YELLOW}No RPC targets found. Skipping RPC Metasploit scan.${NC}"
            echo
        fi
    fi

    if [[ -s "$output_dir/nmap/Oracle.gnmap" ]]; then
        mkdir -p "$output_dir/msforacletnscmd"
        awk '/^Host: / && /Ports:.*1521\/open/ {print $2}' "$output_dir/nmap/Oracle.gnmap" > "$output_dir/oracle_targets.txt"
        if [[ -s "$output_dir/oracle_targets.txt" ]]; then
            echo -e "${GREEN}Starting Oracle TNS Listener SID Enumeration scan.${NC}"
            while IFS= read -r target_ip; do
                if step_completed "msf:oracle:$target_ip"; then
                    skip_notice "msf:oracle:$target_ip" "Oracle TNS Metasploit scan on $target_ip"
                    continue
                fi
                local resource_script="$output_dir/msforacletnscmd/tnscmd_scan_${target_ip}.rc"
                local output_file="$output_dir/msforacletnscmd/oracletnscmd_${target_ip}.txt"
                echo "use auxiliary/admin/oracle/tnscmd" > "$resource_script"
                echo "set RHOSTS $target_ip" >> "$resource_script"
                run_metasploit_scan "$resource_script" "$output_file"
                mark_completed "msf:oracle:$target_ip"
                echo -e "${BLUE}Oracle TNS Listener SID Enumeration scan for $target_ip completed, results saved to $output_file${NC}"
                echo
            done < "$output_dir/oracle_targets.txt"
        else
            echo -e "${YELLOW}No Oracle TNS Listener targets found. Skipping Oracle Metasploit scan.${NC}"
            echo
        fi
    fi

    if [[ -s "$output_dir/nmap/AFP.gnmap" ]]; then
        mkdir -p "$output_dir/msfafp"
        awk '/^Host: / && /Ports:.*548\/open/ {print $2}' "$output_dir/nmap/AFP.gnmap" > "$output_dir/afp_targets.txt"
        if [[ -s "$output_dir/afp_targets.txt" ]]; then
            echo -e "${GREEN}Starting AFP Server Information Disclosure scan.${NC}"
            while IFS= read -r target_ip; do
                if step_completed "msf:afp:$target_ip"; then
                    skip_notice "msf:afp:$target_ip" "AFP Metasploit scan on $target_ip"
                    continue
                fi
                local resource_script="$output_dir/msfafp/afp_scan_${target_ip}.rc"
                local output_file="$output_dir/msfafp/afp_${target_ip}.txt"
                echo "use auxiliary/scanner/afp/afp_server_info" > "$resource_script"
                echo "set RHOSTS $target_ip" >> "$resource_script"
                run_metasploit_scan "$resource_script" "$output_file"
                mark_completed "msf:afp:$target_ip"
                echo -e "${BLUE}AFP Server Information Disclosure scan for $target_ip completed, results saved to $output_file${NC}"
            done < "$output_dir/afp_targets.txt"
        else
            echo -e "${YELLOW}No AFP targets found. Skipping AFP Metasploit scan.${NC}"
            echo
        fi
    fi

    if [[ -s "$output_dir/nmap/NTP.gnmap" ]]; then
        mkdir -p "$output_dir/msfntp"
        awk '/^Host: / && /Ports:.*123\/open/ {print $2}' "$output_dir/nmap/NTP.gnmap" > "$output_dir/ntp_targets.txt"
        if [[ -s "$output_dir/ntp_targets.txt" ]]; then
            echo -e "${GREEN}Starting NTP Amplification Attack.${NC}"
            while IFS= read -r target_ip; do
                if step_completed "msf:ntp:$target_ip"; then
                    skip_notice "msf:ntp:$target_ip" "NTP Metasploit scan on $target_ip"
                    continue
                fi
                local resource_script="$output_dir/msfntp/ntp_scan_${target_ip}.rc"
                local output_file="$output_dir/msfntp/ntp_${target_ip}.txt"
                echo "use auxiliary/scanner/ntp/ntp_peer_list_dos" > "$resource_script"
                echo "set RHOSTS $target_ip" >> "$resource_script"
                run_metasploit_scan "$resource_script" "$output_file"
                mark_completed "msf:ntp:$target_ip"
                echo -e "${BLUE}NTP Amplification Attack for $target_ip completed, results saved to $output_file${NC}"
                echo
            done < "$output_dir/ntp_targets.txt"
        else
            echo -e "${YELLOW}No NTP targets found. Skipping NTP Metasploit scan.${NC}"
            echo
        fi
    fi

    if [[ -s "$output_dir/nmap/SNMP.gnmap" ]]; then
        mkdir -p "$output_dir/msfsnmp"
        awk '/^Host: / && /Ports:.*161\/open/ {print $2}' "$output_dir/nmap/SNMP.gnmap" > "$output_dir/snmp_targets.txt"
        if [[ -s "$output_dir/snmp_targets.txt" ]]; then
            echo -e "${GREEN}Starting SNMP Information Disclosure scan.${NC}"
            while IFS= read -r target_ip; do
                if step_completed "msf:snmp:$target_ip"; then
                    skip_notice "msf:snmp:$target_ip" "SNMP Metasploit scan on $target_ip"
                    continue
                fi
                local resource_script="$output_dir/msfsnmp/snmp_scan_${target_ip}.rc"
                local output_file="$output_dir/msfsnmp/snmp_${target_ip}.txt"
                echo "use auxiliary/scanner/snmp/snmp_login" > "$resource_script"
                echo "set RHOSTS $target_ip" >> "$resource_script"
                run_metasploit_scan "$resource_script" "$output_file"
                mark_completed "msf:snmp:$target_ip"
                echo -e "${BLUE}SNMP Information Disclosure scan for $target_ip completed, results saved to $output_file${NC}"
                echo
            done < "$output_dir/snmp_targets.txt"
        else
            echo -e "${YELLOW}No SNMP targets found. Skipping SNMP Metasploit scan.${NC}"
            echo
        fi
    fi
    echo -e "${BLUE}Metasploit Scans Completed.${NC}\n"
}
