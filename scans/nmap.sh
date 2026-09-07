#!/usr/bin/env bash

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"

# Nmap places no limit on NSE runtime by default, so a script that never
# returns - rdp-enum-encryption against some RDP stacks is the usual culprit -
# hangs the whole scan after "NSE: Script scanning". --script-timeout bounds
# each script per host. Support is probed with a list scan, which sends no
# packets, because --script-timeout is not shown in nmap --help.
NMAP_SCRIPT_TIMEOUT_SUPPORTED=""

nmap_supports_script_timeout() {
    if [ -z "$NMAP_SCRIPT_TIMEOUT_SUPPORTED" ]; then
        if nmap --script-timeout 1m -sL -n 127.0.0.1 >/dev/null 2>&1; then
            NMAP_SCRIPT_TIMEOUT_SUPPORTED="yes"
        else
            NMAP_SCRIPT_TIMEOUT_SUPPORTED="no"
        fi
    fi
    [ "$NMAP_SCRIPT_TIMEOUT_SUPPORTED" = "yes" ]
}

# Echoes the timeout flags to add to every nmap invocation.
nmap_timeout_args() {
    local args=""
    local st
    local ht

    st="$(opt_get script_timeout)"
    [ -z "$st" ] && st="5m"
    case "$st" in
        0|none|off) st="" ;;
    esac
    if [ -n "$st" ] && nmap_supports_script_timeout; then
        args="--script-timeout $st"
    fi

    ht="$(opt_get host_timeout)"
    if [ -n "$ht" ]; then
        case "$ht" in
            0|none|off) ;;
            *) args="$args --host-timeout $ht" ;;
        esac
    fi

    printf '%s' "$args"
}

run_nmap_scans() {
    local output_dir="$1"

    local targets_file="$output_dir/live_hosts.txt"

    # Ordered "name<TAB>nmap arguments" table. Declared in scan order, so no
    # associative array (Bash 4 only) is needed.
    local scripts=()
    table_add scripts "SMB" '-p 139,445 --script smb-security-mode,smb2-security-mode,smb-enum-users.nse,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010'
    table_add scripts "SSLCipher" '--script ssl-enum-ciphers -p 443,1443,389,3389'
    table_add scripts "HTTPSVN" '--script http-svn-enum,http-svn-info -p 443'
    table_add scripts "NetBIOS" '-sU -sV --script nbstat -p137,138,139,445'
    table_add scripts "Oracle" '-sV --script oracle-tns-version,oracle-sid-brute -p 1521'
    table_add scripts "NTP" '-sU -sV --script ntp-monlist,ntp-info -p 123'
    table_add scripts "SNMP" '-sV --script snmp-brute,snmp-info -p161 -vvv'
    table_add scripts "LDAP" '-sV --script ldap*,ldap-search,ldap-novell-getpass -p 389,636,3268,3269'
    table_add scripts "HTTP" '-sV -p 80,81,443,8000,8080,8443 --script http-methods,http-headers,http-iis-webdav-vuln,http-auth-finder,http-apache-server-status,http-traceroute,http-trace,http-vuln*,http-axis2-dir-traversal,http-cross-domain-policy --script-args http-cross-domain-policy.domain-lookup=true'
    table_add scripts "Portmapper" '-sSUC --script nfs-showmount -p111'
    table_add scripts "MySQL" '-sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122'
    table_add scripts "MSSQL" '--script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config -sV -p 1433'
    table_add scripts "SSH" '-p22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods --script-args ssh_hostkey=full,ssh.user=root'
    table_add scripts "Telnet" '-sV --script telnet-brute,telnet-encryption,lu-enum,cics-info --script-args cics-info.user=test,cics-info.pass=test,cics-info.cemt='"'"'ZEMT'"'"',cics-info.trans=CICA -p 23'
    table_add scripts "DNS" '--script default,dns-fuzz,dns-brute,dns-cache-snoop -p 53'
    table_add scripts "Pop3" '--script pop3-capabilities,pop3-ntlm-info -sV -p 110'
    table_add scripts "NFS" '--script nfs-ls,nfs-showmount,nfs-statfs -p 2049'
    table_add scripts "RDP" '--script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info -p 3389'
    table_add scripts "RPC" '-p 135'
    table_add scripts "ApacheAJP" '-sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -p 8009'
    table_add scripts "FTP" '--script ftp-anon --script-args ftp-anon.maxlist=-1 -p 21'
    table_add scripts "TFTP" '-sU -p69 -sV --script tftp-enum'
    table_add scripts "RTSP" '-sV --script rtsp-*,rtsp-url-brute -p 554'
    table_add scripts "WildcardCertificate" '--script ssl-cert -p443'
    table_add scripts "SMTP" '--script smtp-commands,smtp-open-relay,smtp-enum-users -p 25,465,587'
    table_add scripts "IPMI" '-sU --script ipmi-brute,ipmi-cipher-zero -p 623'
    table_add scripts "IMAP" '--script imap-brute,imap-ntlm-info -p 143,993'
    table_add scripts "IKE" '-sU -sV --script ike-version -p 500'
    table_add scripts "AFP" '-sS -sV --script afp-showmount,afp-ls -p 548'
    table_add scripts "Gopher" '--script gopher-ls --script-args gopher-ls.maxfiles=100 -p 70'
    # The NSE realm defaults to 'test' as before, but follows --domain when given.
    local krb_realm
    krb_realm="$(opt_get kerberos_domain)"
    [ -z "$krb_realm" ] && krb_realm="test"
    table_add scripts "Kerberos" "--script krb5-enum-users --script-args krb5-enum-users.realm='$krb_realm' -p 88"
    table_add scripts "PJL" '--script pjl-ready-message.nse --script-args '"'"'pjl_ready_message="pwn3d!"'"'"' -p 9100'
    table_add scripts "Redis" '--script redis-info,redis-brute -p 6379'
    table_add scripts "RealVNC" '--script realvnc-auth-bypass -p 5900'
    table_add scripts "SIP" '-sU --script sip-enum-users,sip-brute -p 5060'
    table_add scripts "TCP" '-sC -sV'
    table_add scripts "UDP" '-sC -sU'
    table_add scripts "AllPorts" '-p-'

    local excluded=""
    if opt_true exclude_udp; then
        echo -e "${YELLOW}• Excluding 'UDP' scripts.${NC}\n"
        excluded=" UDP"
    fi

    if opt_true exclude_allports; then
        echo -e "${YELLOW}• Excluding 'UDP' and 'AllPorts' scripts.${NC}\n"
        excluded=" UDP AllPorts"
    fi

    if [ -n "$excluded" ]; then
        local kept=()
        local entry
        for entry in "${scripts[@]}"; do
            case " $excluded " in
                *" $(table_key "$entry") "*) continue ;;
            esac
            arr_push kept "$entry"
        done
        scripts=("${kept[@]}")
    fi

    local additional_nmap_scripts=()
    if opt_true vulners; then
        echo -e "${YELLOW}• Adding 'vulners' script.${NC}\n"
        arr_push additional_nmap_scripts "vulners"
    fi
    if opt_true vuln; then
        echo -e "${YELLOW}• Adding 'vuln' script.${NC}\n"
        arr_push additional_nmap_scripts "vuln"
    fi

    local suffix=""
    local prefix=""

    if [ ${#additional_nmap_scripts[@]} -gt 0 ]; then
        suffix=" --script ${additional_nmap_scripts[*]}"
    fi

    if opt_true add_nT4; then
        echo -e "${YELLOW}• Adding -n -T4 to accelerate scans.${NC}\n"
        prefix="-n -T4 $prefix"
    fi

    if opt_true add_A_minrate_open; then
        echo -e "${YELLOW}• Adding '--min-rate 1000 --open' for a boost and open ports only.${NC}\n"
        prefix="--min-rate 1000 --open $prefix"
    fi

    if [ -n "$prefix" ] || [ -n "$suffix" ]; then
        local rebuilt=()
        local entry
        for entry in "${scripts[@]}"; do
            arr_push rebuilt "$(table_key "$entry")$LZ_TAB${prefix}$(table_value "$entry")${suffix}"
        done
        scripts=("${rebuilt[@]}")
    fi

    local timeout_args
    timeout_args="$(nmap_timeout_args)"
    if [ -n "$timeout_args" ]; then
        echo -e "${YELLOW}• NSE guard: ${timeout_args}${NC}\n"
    else
        echo -e "${YELLOW}• NSE guard disabled: a hanging script can stall the scan.${NC}\n"
    fi

    local entry
    for entry in "${scripts[@]}"; do
        script_name="$(table_key "$entry")"
        script_args="$(table_value "$entry")"
        if [ -z "$script_args" ]; then continue; fi

        if step_completed "nmap:$script_name"; then
            skip_notice "nmap:$script_name" "${script_name} nmap scan"
            continue
        fi

        echo -e "${GREEN}Starting ${script_name} scan.${NC}"

        nmap_output_file="$output_dir/nmap/${script_name}.txt"

        # Greppable output comes from this same scan. It used to be produced by
        # a second "nmap -sV -oG" run with no -p and no -v: a silent top-1000
        # port version sweep of every live host, repeated for 13 modules, which
        # ignored -n/-T4/--min-rate and looked like the scan had hung.
        nmap $script_args $timeout_args -v --reason --stats-every 30s \
            -oN "$nmap_output_file" \
            -oG "$output_dir/nmap/${script_name}.gnmap" \
            -iL "$targets_file"

        mark_completed "nmap:$script_name"
        echo -e "${GREEN}Completed ${script_name} scan. Output saved to ${nmap_output_file}.${NC}\n"
    done

    echo -e "${BLUE}======================================================${NC}"
    echo -e "${BLUE}All nmap scans completed. Starting service-specific checks.${NC}"
    echo -e "${BLUE}======================================================${NC}\n"
}

run_firewall_evasion_scans() {
    local output_dir="$1"

    local targets_file="$output_dir/live_hosts.txt"

    # Ordered "name<TAB>arguments" table, listed in the same sorted order the
    # previous associative-array version iterated in.
    local firewall_evasion_scripts=()
    table_add firewall_evasion_scripts "BadChecksum" '--badsum'
    table_add firewall_evasion_scripts "ExoticFlag" '-sF -p1-100 -T4'
    table_add firewall_evasion_scripts "FragmentPackets" '-f'
    table_add firewall_evasion_scripts "ICMPEchoRequest" '-n -sn -PE -T4'
    table_add firewall_evasion_scripts "MACSpoofASUS" '-sT -PO --spoof-mac ASUS -Pn'
    table_add firewall_evasion_scripts "MACSpoofApple" '-sT -PO --spoof-mac Apple -Pn'
    table_add firewall_evasion_scripts "MACSpoofBroadcom" '-sT -PO --spoof-mac Broadcom -Pn'
    table_add firewall_evasion_scripts "MACSpoofCisco" '-sT -PO --spoof-mac Cisco -Pn'
    table_add firewall_evasion_scripts "MACSpoofDell" '-sT -PO --spoof-mac Dell -Pn'
    table_add firewall_evasion_scripts "MACSpoofHP" '-sT -PO --spoof-mac HP -Pn'
    table_add firewall_evasion_scripts "MACSpoofIntel" '-sT -PO --spoof-mac Intel -Pn'
    table_add firewall_evasion_scripts "MACSpoofJuniper" '-sT -PO --spoof-mac Juniper -Pn'
    table_add firewall_evasion_scripts "MACSpoofMicrosoft" '-sT -PO --spoof-mac Microsoft -Pn'
    table_add firewall_evasion_scripts "MACSpoofNetgear" '-sT -PO --spoof-mac Netgear -Pn'
    table_add firewall_evasion_scripts "MACSpoofSamsung" '-sT -PO --spoof-mac Samsung -Pn'
    table_add firewall_evasion_scripts "MACSpoofSony" '-sT -PO --spoof-mac Sony -Pn'
    table_add firewall_evasion_scripts "MACSpoofTP-Link" '-sT -PO --spoof-mac TP-Link -Pn'
    table_add firewall_evasion_scripts "MTU" '--mtu 16'
    table_add firewall_evasion_scripts "PacketTrace" '-vv -n -sn -PE -T4 --packet-trace'
    table_add firewall_evasion_scripts "SourcePort" '-g 53 -Pn'
    table_add firewall_evasion_scripts "SourcePortCheck" '-sSUC --script source-port -Pn'

    local timeout_args
    timeout_args="$(nmap_timeout_args)"

    local entry
    for entry in "${firewall_evasion_scripts[@]}"; do
        script_name="$(table_key "$entry")"
        script_args="$(table_value "$entry")"
        if step_completed "fw:$script_name"; then
            skip_notice "fw:$script_name" "${script_name} firewall evasion scan"
            continue
        fi

        echo -e "${GREEN}Starting scan for ${script_name}.${NC}"

        nmap_output_file="$output_dir/nmap/firewall_evasion/${script_name}.txt"
        mkdir -p "$(dirname "$nmap_output_file")"

        nmap $script_args $timeout_args -v --reason --stats-every 30s -oN "$nmap_output_file" -iL "$targets_file"

        mark_completed "fw:$script_name"
        echo -e "${GREEN}Completed ${script_name} scan.${NC}\n"
    done
}
