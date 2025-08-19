#!/bin/bash
# Functions for running Nmap scans

initialize_nmap_scripts() {
    NMAP_SCRIPTS=(
        ["SMB"]='-p 139,445 --script smb-security-mode,smb2-security-mode,smb-enum-users.nse,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010 -oN results/smbsec.txt -v'
        ["SSLCipher"]='--script ssl-enum-ciphers -p 443,1443,389,3389 -oN results/sslcipher.txt -v'
        ["HTTPSVN"]='--script http-svn-enum,http-svn-info -p 443 -oN results/httpsvnenum.txt -v'
        ["NetBIOS"]='-n -Pn -p 137,139,445 --script nbstat,smb-os-discovery -oN results/netbiosinfodis.txt -v'
        ["Oracle"]='--script oracle-tns-version,oracle-sid-brute -p 1521 -T4 -sV -oN results/oracle.txt -oG results/oracle.gnmap -v'
        ["NTP"]='-sV --script ntp-monlist,ntp-info -p 123 -oN results/ntpservice.txt -v'
        ["SNMP"]='-sV --script snmp-info,snmp-brute -p161 -vvv -oN results/snmpinfodis.txt -v'
        ["LDAP"]='-n -sV --script ldap*,ldap-search,ldap-novell-getpass -p 389,636,3268,3269 -oN results/ldap.txt -oG results/ldap.gnmap -v'
        ["HTTP"]='-sV -p 80,81,443,8000,8080,8443 --script http-headers,http-iis-webdav-vuln,http-auth-finder,http-apache-server-status,http-traceroute,http-trace,http-vuln*,http-axis2-dir-traversal,http-cross-domain-policy --script-args http-cross-domain-policy.domain-lookup=true -oN results/http.txt -oG results/http.gnmap -v'
        ["Portmapper"]='-sSUC --script nfs-showmount -p111 -oN results/portmapper111.txt -v'
        ["MySQL"]='-sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -oN results/mysql.txt -v'
        ["MSSQL"]='--script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config -sV -p 1433 -oN results/mssql.txt -v'
        ["SSH"]='-p22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods --script-args ssh_hostkey=full,ssh.user=root -oN results/ssh.txt -v'
        ["Telnet"]='-n -sV -Pn --script telnet-brute,telnet-encryption,lu-enum,cics-info --script-args cics-info.user=test,cics-info.pass=test,cics-info.cemt='"'"'ZEMT'"'"',cics-info.trans=CICA -p 23 -oN results/telnetservice.txt -v'
        ["DNS"]='-n --script default,dns-fuzz,dns-brute,dns-cache-snoop -p 53 -oN results/dnsvuln.txt -oG results/dnsvuln.gnmap -v'
        ["Pop3"]='--script pop3-capabilities,pop3-ntlm-info -sV -p 110 -oN results/pop3.txt -v'
        ["NFS"]='--script nfs-ls,nfs-showmount,nfs-statfs -p 2049 -oN results/nfs.txt -v'
        ["RDP"]='--script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info -p 3389 -T4 -oN results/rdpscript.txt -oG results/rdp.gnmap -v'
        ["RPC"]='-p 135 -T4 -oN results/rpc.txt -oG results/rpc.gnmap -v'
        ["ApacheAJP"]='-sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 -oN results/apacheajp.txt -v'
        ["FTP"]='--script ftp-anon --script-args ftp-anon.maxlist=-1 -p 21 -oN results/ftp.txt -v'
        ["TFTP"]='-n -Pn -p69 -sV --script tftp-enum -oN results/tftp.txt -v'
        ["RTSP"]='-sV --script rtsp-*,rtsp-url-brute -p 554 -oN results/rtsp.txt -v'
        ["WildcardCertificate"]='--script ssl-cert -p443 -oN results/wildcardcert.txt -v'
        ["SMTP"]='--script smtp-commands,smtp-open-relay,smtp-enum-users -p 25,465,587 -oN results/smtp.txt -v'
        ["IPMI"]='--script ipmi-brute,ipmi-cipher-zero -p 623 -oN results/ipmi.txt -v'
        ["IMAP"]='--script imap-brute,imap-ntlm-info -p 143,993 -oN results/imap.txt -v'
        ["IKE"]='-sV --script ike-version -p 500 -oN results/ike.txt -v'
        ["AFP"]='-sS -sV --script afp-showmount,afp-ls -p 548 -oN results/afp.txt -v'
        ["Gopher"]='--script gopher-ls --script-args gopher-ls.maxfiles=100 -p 70 -oN results/gopher.txt -v'
        ["Kerberos"]='--script krb5-enum-users --script-args krb5-enum-users.realm='"'"'test'"'"' -p 88 -oN results/kerberos.txt -v'
        ["PJL"]='--script pjl-ready-message.nse --script-args '"'"'pjl_ready_message="pwn3d!"'"'"' -oN results/pjl.txt -v'
        ["Redis"]='--script redis-info,redis-brute -p 6379 -oN results/redis.txt -v'
        ["RealVNC"]='--script realvnc-auth-bypass -p 5900 -oN results/realvnc.txt -v'
        ["SIP"]='--script sip-brute,sip-call-spoof,sip-enum-users --script-args '"'"'sip-enum-users.padding=4,sip-enum-users.minext=1000,sip-enum-users.maxext=9999'"'"' -p 5060 -oN results/sip.txt -v'
        ["TCP"]='-sC -sV -oN results/tcp.txt -oG results/tcp.gnmap -v --reason'
        ["UDP"]='-sC -sU -T4 -oN results/udp.txt -v --reason'
        ["AllPorts"]='-p- -T4 -oN results/allports.txt -v --reason'
    )

    ordered_scripts=(
        "SMB" "SSLCipher" "HTTPSVN" "NetBIOS" "Oracle" "NTP" "SNMP" "LDAP" "HTTP"
        "Portmapper" "MySQL" "MSSQL" "SSH" "Telnet" "DNS" "Pop3" "NFS" "RDP" "RPC"
        "ApacheAJP" "FTP" "TFTP" "RTSP" "WildcardCertificate" "SMTP" "IPMI" "IMAP"
        "IKE" "AFP" "Gopher" "Kerberos" "PJL" "Redis" "RealVNC" "SIP" "TCP" "UDP" "AllPorts"
    )
}

apply_nmap_options() {
    local additional_scripts=()
    if [[ "$add_vulners" = true ]]; then
        echo -e "${YELLOW}• Starting scans with option -1 (vulners).${NC}\n"
        additional_scripts+=("vulners")
    fi
    if [[ "$add_vuln" = true ]]; then
        echo -e "${YELLOW}• Starting scans with option -2 (vuln).${NC}\n"
        additional_scripts+=("vuln")
    fi

    if [[ -n "${additional_scripts[*]}" ]]; then
        IFS=',' read -r -a unique_scripts <<< "$(printf "%s\n" "${additional_scripts[@]}" | sort -u | paste -sd, -)"
        for key in "${!NMAP_SCRIPTS[@]}"; do
            if [[ "${NMAP_SCRIPTS[$key]}" == *"--script "* ]]; then
                existing_scripts="${NMAP_SCRIPTS[$key]#*--script }"
                NMAP_SCRIPTS[$key]="--script ${unique_scripts[*]},$existing_scripts"
            fi
        done
    fi

    if [[ "$add_nT4" = true ]]; then
        echo -e "${YELLOW}• Adding -n -T4 to accelerate associative array scans.${NC}\n"
        for key in "${!NMAP_SCRIPTS[@]}"; do
            NMAP_SCRIPTS[$key]="-n -T4 ${NMAP_SCRIPTS[$key]}"
        done
    fi

    if [[ "$add_A_minrate_open" = true ]]; then
        echo -e "${YELLOW}• Adding '--min-rate 1000 --open' for additional boost and open ports only results.${NC}\n"
        for key in "${!NMAP_SCRIPTS[@]}"; do
            NMAP_SCRIPTS[$key]="--min-rate 1000 --open ${NMAP_SCRIPTS[$key]}"
        done
    fi

    if [[ "$a_option_set" = true ]]; then
        echo -e "${YELLOW}• Starting scans without 'UDP' and 'AllPorts' scripts.${NC}\n"
        ordered_scripts=($(printf "%s\n" "${ordered_scripts[@]}" | grep -v -E "^(UDP|AllPorts)$"))
    fi
}

run_nmap_scans() {
    local targets_file=$1
    local single_target=$2

    for script_name in "${ordered_scripts[@]}"; do
        [[ -z "$script_name" ]] && continue
        if [[ -z "${NMAP_SCRIPTS[$script_name]}" ]]; then
            echo -e "${RED}Warning: Script '$script_name' not found in scripts array.${NC}"
            continue
        fi

        script_args="${NMAP_SCRIPTS[$script_name]}"
        if [[ -z "$script_args" ]]; then
            continue
        fi

        if [[ -n "$targets_file" && -s "$targets_file" ]]; then
            echo -e "${GREEN}Starting ${script_name} scan.${NC}"
            nmap $script_args -iL "$targets_file"
            echo -e "${GREEN}Completed ${script_name} scan.${NC}\n"
        elif [[ -n "$single_target" ]]; then
            echo -e "${GREEN}Starting ${script_name} scan.${NC}"
            nmap $script_args "$single_target"
            echo -e "${GREEN}Completed ${script_name} scan.${NC}\n\n"
        else
            echo -e "${RED}No valid targets found for ${script_name} scan. Skipping.${NC}\n"
        fi
    done
    echo -e "${BLUE}Nmap scans completed, output files saved to results directory.${NC}"
    echo -e "\n--------------------------------\n"
}
