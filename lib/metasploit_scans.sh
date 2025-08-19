#!/bin/bash
# Functions for running Metasploit scans

run_metasploit_scans() {
    if [[ -f "results/rdp.gnmap" ]]; then
        echo -e "${YELLOW}Starting Metasploit Scan.${NC}"
        echo -e "\n${YELLOW}Extracting RDP (port 3389) open IPs from rdp.gnmap.${NC}"
        awk '/^Host: / && /3389\/open/{print $2}' results/rdp.gnmap > results/rdp_targets.txt
        scan_rdp "results/rdp_targets.txt"
        rm results/rdp_targets.txt
    else
        echo -e "${YELLOW}No RDP targets found. Skipping RDP Metasploit scan.${NC}\n"
    fi

    if [[ -f "results/rpc.gnmap" ]]; then
        echo -e "\n${YELLOW}Extracting RPC (port 135) open IPs from rpc.gnmap.${NC}"
        awk '/^Host: / && /135\/open/{print $2}' results/rpc.gnmap > results/rpc_targets.txt
        scan_rpc "results/rpc_targets.txt"
        rm results/rpc_targets.txt
    else
        echo -e "${YELLOW}No RPC targets found. Skipping RPC Metasploit scan.${NC}\n"
    fi

    if [[ -f "results/oracle.gnmap" ]]; then
        echo -e "\n${YELLOW}Extracting Oracle (port 1521) open IPs from oracle.gnmap.${NC}"
        awk '/^Host: / && /1521\/open/{print $2}' results/oracle.gnmap > results/oracle_targets.txt
        scan_oracle "results/oracle_targets.txt"
        rm results/oracle_targets.txt
    else
        echo -e "${YELLOW}No Oracle targets found. Skipping Oracle Metasploit scan.${NC}\n"
    fi
    echo -e "${BLUE}Metasploit scans completed, output files saved to their respective directories.${NC}"
    echo -e "\n--------------------------------\n"
}

scan_rdp() {
    local targets_file=$1
    if [[ -s "$targets_file" ]]; then
        mkdir -p results/msfrdp
        echo -e "${GREEN}Starting RDP (Remote Desktop Protocol) scan."
        while IFS= read -r target_ip; do
            echo -e "${GREEN}Scanning RDP on $target_ip${NC}"
            local resource_script="results/msfrdp/rdp_scan_${target_ip}.rc"
            local output_file="results/msfrdp/rdp_${target_ip}.txt"
            echo "use auxiliary/scanner/rdp/rdp_scanner" > "$resource_script"
            echo "set RHOSTS $target_ip" >> "$resource_script"
            echo "set THREADS 1" >> "$resource_script"
            echo "spool $output_file" >> "$resource_script"
            echo "run" >> "$resource_script"
            echo "spool off" >> "$resource_script"
            echo "exit" >> "$resource_script"
            msfconsole -q -r "$resource_script"
            echo -e "${BLUE}RDP scan for $target_ip completed, results saved to $output_file${NC}"
            echo -e "\n--------------------------------\n"
        done < "$targets_file"
    fi
}

scan_rpc() {
    local targets_file=$1
    if [[ -s "$targets_file" ]]; then
        mkdir -p results/msfrpc
        echo -e "${GREEN}Starting RPC (Remote Procedure Call) scan.${NC}"
        while IFS= read -r target_ip; do
            echo -e "${GREEN}Scanning RPC on $target_ip${NC}"
            local resource_script="results/msfrpc/rpc_scan_${target_ip}.rc"
            local output_file="results/msfrpc/rpc_${target_ip}.txt"
            echo "use auxiliary/scanner/dcerpc/endpoint_mapper" > "$resource_script"
            echo "set RHOSTS $target_ip" >> "$resource_script"
            echo "set THREADS 1" >> "$resource_script"
            echo "spool $output_file" >> "$resource_script"
            echo "run" >> "$resource_script"
            echo "spool off" >> "$resource_script"
            echo "exit" >> "$resource_script"
            msfconsole -q -r "$resource_script"
            echo -e "${BLUE}RPC scan for $target_ip completed, results saved to $output_file${NC}"
            echo -e "\n--------------------------------\n"
        done < "$targets_file"
    fi
}

scan_oracle() {
    local targets_file=$1
    if [[ -s "$targets_file" ]]; then
        mkdir -p results/msforacletnscmd
        echo -e "${GREEN}Starting Oracle TNS Listener SID Enumeration scan.${NC}"
        while IFS= read -r target_ip; do
            echo -e "${GREEN}Scanning Oracle TNS Listener on $target_ip${NC}"
            local resource_script="results/msforacletnscmd/tnscmd_scan_${target_ip}.rc"
            local output_file="results/msforacletnscmd/oracletnscmd_${target_ip}.txt"
            echo "use auxiliary/admin/oracle/tnscmd" > "$resource_script"
            echo "set RHOSTS $target_ip" >> "$resource_script"
            echo "set THREADS 1" >> "$resource_script"
            echo "spool $output_file" >> "$resource_script"
            echo "run" >> "$resource_script"
            echo "spool off" >> "$resource_script"
            echo "exit" >> "$resource_script"
            msfconsole -q -r "$resource_script"
            echo -e "${BLUE}Oracle TNS Listener SID Enumeration scan for $target_ip completed, results saved to $output_file${NC}\n"
        done < "$targets_file"
    fi
}