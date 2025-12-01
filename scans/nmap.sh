#!/usr/bin/env bash

# scans/nmap.sh
# Manages all selected nmap scans.

source "lib/colors.sh"

run_nmap_scans() {
    local output_dir="$1"

    # Use the live_hosts.txt file as the target list
    local targets_file="$output_dir/live_hosts.txt"

    # Define Nmap scripts
    declare -A scripts=(
        ["SMB"]='-p 139,445 --script smb-security-mode,smb2-security-mode,smb-enum-users.nse,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010'
        ["SSLCipher"]='--script ssl-enum-ciphers -p 443,1443,389,3389'
        ["HTTPSVN"]='--script http-svn-enum,http-svn-info -p 443'
        ["NetBIOS"]='-sU -sV --script nbstat -p137,138,139,445'
        ["Oracle"]='-sV --script oracle-tns-version,oracle-sid-brute -p 1521'
        ["NTP"]='-sU -sV --script ntp-monlist,ntp-info -p 123'
        ["SNMP"]='-sV --script snmp-brute,snmp-info -p161 -vvv'
        ["LDAP"]='-sV --script ldap*,ldap-search,ldap-novell-getpass -p 389,636,3268,3269'
        ["HTTP"]='-sV -p 80,81,443,8000,8080,8443 --script http-methods,http-headers,http-iis-webdav-vuln,http-auth-finder,http-apache-server-status,http-traceroute,http-trace,http-vuln*,http-axis2-dir-traversal,http-cross-domain-policy --script-args http-cross-domain-policy.domain-lookup=true'
        ["Portmapper"]='-sSUC --script nfs-showmount -p111'
        ["MySQL"]='-sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122'
        ["MSSQL"]='--script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config -sV -p 1433'
        ["SSH"]='-p22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods --script-args ssh_hostkey=full,ssh.user=root'
        ["Telnet"]='-sV --script telnet-brute,telnet-encryption,lu-enum,cics-info --script-args cics-info.user=test,cics-info.pass=test,cics-info.cemt='"'"'ZEMT'"'"',cics-info.trans=CICA -p 23'
        ["DNS"]='--script default,dns-fuzz,dns-brute,dns-cache-snoop -p 53'
        ["Pop3"]='--script pop3-capabilities,pop3-ntlm-info -sV -p 110'
        ["NFS"]='--script nfs-ls,nfs-showmount,nfs-statfs -p 2049'
        ["RDP"]='--script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info -p 3389'
        ["RPC"]='-p 135'
        ["ApacheAJP"]='-sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -p 8009'
        ["FTP"]='--script ftp-anon --script-args ftp-anon.maxlist=-1 -p 21'
        ["TFTP"]='-sU -p69 -sV --script tftp-enum'
        ["RTSP"]='-sV --script rtsp-*,rtsp-url-brute -p 554'
        ["WildcardCertificate"]='--script ssl-cert -p443'
        ["SMTP"]='--script smtp-commands,smtp-open-relay,smtp-enum-users -p 25,465,587'
        ["IPMI"]='-sU --script ipmi-brute,ipmi-cipher-zero -p 623'
        ["IMAP"]='--script imap-brute,imap-ntlm-info -p 143,993'
        ["IKE"]='-sU -sV --script ike-version -p 500'
        ["AFP"]='-sS -sV --script afp-showmount,afp-ls -p 548'
        ["Gopher"]='--script gopher-ls --script-args gopher-ls.maxfiles=100 -p 70'
        ["Kerberos"]='--script krb5-enum-users --script-args krb5-enum-users.realm='"'"'test'"'"' -p 88'
        ["PJL"]='--script pjl-ready-message.nse --script-args '"'"'pjl_ready_message="pwn3d!"'"'"' -p 9100'
        ["Redis"]='--script redis-info,redis-brute -p 6379'
        ["RealVNC"]='--script realvnc-auth-bypass -p 5900'
        ["SIP"]='-sU --script sip-enum-users,sip-brute -p 5060'
        ["TCP"]='-sC -sV'
        ["UDP"]='-sC -sU'
        ["AllPorts"]='-p-'
    )

    # Specify the order in which the scripts should be executed
    ordered_scripts=(
        "SMB" "SSLCipher" "HTTPSVN" "NetBIOS" "Oracle" "NTP" "SNMP" "LDAP" "HTTP"
        "Portmapper" "MySQL" "MSSQL" "SSH" "Telnet" "DNS" "Pop3" "NFS" "RDP" "RPC"
        "ApacheAJP" "FTP" "TFTP" "RTSP" "WildcardCertificate" "SMTP" "IPMI" "IMAP"
        "IKE" "AFP" "Gopher" "Kerberos" "PJL" "Redis" "RealVNC" "SIP" "TCP" "UDP" "AllPorts"
    )

    # Exclude UDP if --exclude-udp is specified
    if [[ "${OPTIONS[exclude_udp]}" == true ]]; then
        echo -e "${YELLOW}• Excluding 'UDP' scripts.${NC}\n"
        ordered_scripts=($(printf "%s\n" "${ordered_scripts[@]}" | grep -v -E "^(UDP)$"))
    fi

    # Exclude UDP and All Ports if -a is specified
    if [[ "${OPTIONS[exclude_allports]}" == true ]]; then
        echo -e "${YELLOW}• Excluding 'UDP' and 'AllPorts' scripts.${NC}\n"
        ordered_scripts=($(printf "%s\n" "${ordered_scripts[@]}" | grep -v -E "^(UDP|AllPorts)$"))
    fi

    # Accumulate additional Nmap scripts based on options
    additional_nmap_scripts=()
    if [[ "${OPTIONS[vulners]}" == true ]]; then
        echo -e "${YELLOW}• Adding 'vulners' script.${NC}\n"
        additional_nmap_scripts+=("vulners")
    fi
    if [[ "${OPTIONS[vuln]}" == true ]]; then
        echo -e "${YELLOW}• Adding 'vuln' script.${NC}\n"
        additional_nmap_scripts+=("vuln")
    fi

    # Add the accumulated scripts to each Nmap script entry
    if [[ -n "$additional_nmap_scripts" ]]; then
        for key in "${!scripts[@]}"; do
            scripts[$key]+=" --script ${additional_nmap_scripts[*]}"
        done
    fi

    # Add -n -T4 to Nmap scripts if -n is specified
    if [[ "${OPTIONS[add_nT4]}" == true ]]; then
        echo -e "${YELLOW}• Adding -n -T4 to accelerate scans.${NC}\n"
        for key in "${!scripts[@]}"; do
            scripts[$key]="-n -T4 ${scripts[$key]}"
        done
    fi

    # Add --min-rate 1000 --open if -b is specified
    if [[ "${OPTIONS[add_A_minrate_open]}" == true ]]; then
        echo -e "${YELLOW}• Adding '--min-rate 1000 --open' for a boost and open ports only.${NC}\n"
        for key in "${!scripts[@]}"; do
            scripts[$key]="--min-rate 1000 --open ${scripts[$key]}"
        done
    fi

    # Main scanning loop
    for script_name in "${ordered_scripts[@]}"; do
        if [[ -z "${scripts[$script_name]}" ]]; then continue; fi

        script_args="${scripts[$script_name]}"
        echo -e "${GREEN}Starting ${script_name} scan.${NC}"

        # Corrected file path and added -oG for grepable format
        nmap_output_file="$output_dir/nmap/${script_name}.txt"

        # Use the live_hosts.txt file as the target input
        nmap $script_args -v --reason -oN "$nmap_output_file" -iL "$targets_file"

        # Add a second output for metasploit scan
        if [[ "$script_name" == "Oracle" || "$script_name" == "RDP" || "$script_name" == "RPC" || "$script_name" == "AFP" || "$script_name" == "NTP" || "$script_name" == "LDAP" || "$script_name" == "DNS" || "$script_name" == "SNMP" || "$script_name" == "SSH" || "$script_name" == "SSLCipher" ]]; then
            nmap -sV -oG "$output_dir/nmap/${script_name}.gnmap" -iL "$targets_file"
        fi

        echo -e "${GREEN}Completed ${script_name} scan. Output saved to ${nmap_output_file}.${NC}\n"
    done

    echo -e "${BLUE}Nmap associative scans completed.${NC}\n"
}

run_firewall_evasion_scans() {
    local output_dir="$1"

    # Use the live_hosts.txt file as the target list
    local targets_file="$output_dir/live_hosts.txt"

    declare -A firewall_evasion_scripts=(
        ["FragmentPackets"]='-f'
        ["MTU"]='-mtu 16'
        ["MACSpoofApple"]='-sT -PO --spoof-mac Apple -Pn'
        ["MACSpoofCisco"]='-sT -PO --spoof-mac Cisco -Pn'
        ["MACSpoofMicrosoft"]='-sT -PO --spoof-mac Microsoft -Pn'
        ["MACSpoofIntel"]='-sT -PO --spoof-mac Intel -Pn'
        ["MACSpoofSamsung"]='-sT -PO --spoof-mac Samsung -Pn'
        ["MACSpoofDell"]='-sT -PO --spoof-mac Dell -Pn'
        ["MACSpoofHP"]='-sT -PO --spoof-mac HP -Pn'
        ["MACSpoofSony"]='-sT -PO --spoof-mac Sony -Pn'
        ["MACSpoofNetgear"]='-sT -PO --spoof-mac Netgear -Pn'
        ["MACSpoofTP-Link"]='-sT -PO --spoof-mac TP-Link -Pn'
        ["MACSpoofASUS"]='-sT -PO --spoof-mac ASUS -Pn'
        ["MACSpoofJuniper"]='-sT -PO --spoof-mac Juniper -Pn'
        ["MACSpoofBroadcom"]='-sT -PO --spoof-mac Broadcom -Pn'
        ["BadChecksum"]='--badsum'
        ["ExoticFlag"]='-sF -p1-100 -T4'
        ["SourcePortCheck"]='-sSUC --script source-port -Pn'
        ["SourcePort"]='-g -Pn'
        ["ICMPEchoRequest"]='-n -sn -PE -T4'
        ["PacketTrace"]='-vv -n -sn -PE -T4 --packet-trace'
    )

    for script_name in "${!firewall_evasion_scripts[@]}"; do
        script_args="${firewall_evasion_scripts[$script_name]}"
        echo -e "${GREEN}Starting scan for ${script_name}.${NC}"

        # Corrected file path
        nmap_output_file="$output_dir/nmap/firewall_evasion/${script_name}.txt"
        mkdir -p "$(dirname "$nmap_output_file")"

        # Use the live_hosts.txt file as the target input
        nmap $script_args -v --reason -oN "$nmap_output_file" -iL "$targets_file"

        echo -e "${GREEN}Completed ${script_name} scan.${NC}\n"
    done
}
