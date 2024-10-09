#!/bin/bash
# Title: lazymap
# Description: Lazymap is a single command-line tool made for network penetration testing.
# It combines multiple selected NMAP scripts, sslscan, ssh-audit, dig, ldapsearch, curl, rpcclient, selected metasploit modules, and wget.
# Author: Evan Ricafort - https://evanricafort.com | X: @evanricafort

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check for Bash version 4 or higher
if ((BASH_VERSINFO[0] < 4)); then
    echo -e "${RED}Error: This script requires Bash version 4 or higher.${NC}"
    exit 1
fi

# Display functions
display_ascii_art() {
    echo -e "[..            [.       [....... [..[..      [..[..       [..      [.       [.......  "
    echo -e "[..           [. ..            [..   [..    [.. [. [..   [...     [. ..     [..    [.."
    echo -e "[..          [.  [..          [..     [.. [..   [.. [.. [ [..    [.  [..    [..    [.."
    echo -e "[..         [..   [..       [..         [..     [..  [..  [..   [..   [..   [.......  "
    echo -e "[..        [...... [..     [..          [..     [..   [.  [..  [...... [..  [..       "
    echo -e "[..       [..       [..  [..            [..     [..       [.. [..       [.. [..       "
    echo -e "[........[..         [..[...........    [..     [..       [..[..         [..[..  v0.6 "
    echo ""
}

display_help() {
    echo -e "${GREEN}Name: Lazymap (Project0x01)${NC}"
    echo -e "${YELLOW}Author: Evan Ricafort (X - @evanricafort | Portfolio - https://evanricafort.com)${NC}"
    echo -e "${GREEN}Description: Lazymap is a single command-line tool made for network penetration testing. It combines multiple selected NMAP scripts, sslscan, ssh-audit, dig, ldapsearch, curl, rpcclient, selected metasploit modules, and wget.${NC}"
    echo ""
    echo -e "${GREEN}--Usage--${NC}"
    echo ""
    echo -e "${GREEN}- ./lazymap.sh -u host [Single Host] or ./lazymap.sh -t hosts.txt [Multiple Hosts]${NC}"
    echo -e "${GREEN}- Additional Options:${NC}"
    echo -e "  ${YELLOW}-1${NC} ${GREEN}for [vulners],${NC}"
    echo -e "  ${YELLOW}-2${NC} ${GREEN}for [vuln],${NC}"
    echo -e "  ${YELLOW}-3${NC} ${GREEN}for both [vulners & vuln] NSE scripts,${NC}"
    echo -e "  ${YELLOW}-4${NC} ${GREEN}for Firewall Evasion Scan,${NC}"
    echo -e "  ${YELLOW}-a${NC} ${GREEN}to exclude the all ports scan and UDP scan.${NC}"
    echo -e "  ${YELLOW}-N${NC} ${GREEN}to add -n -T4 to Nmap command for faster scanning.${NC}"
    echo -e "  ${YELLOW}-k${NC} ${GREEN}to exclude sslscan, ssh-audit, and CheckThatHeaders scans.${NC}"
    echo -e "  ${YELLOW}-h${NC} ${GREEN}to display this help message.${NC}"
    echo ""
    echo -e "${GREEN}- Reminder: Option -3 may take some time to finish if you have multiple targets.${NC}"
    echo ""
    echo -e "${GREEN}- Note: Run in sudo mode to execute NMAP scripts related to UDP scan.${NC}"
    exit 0
}

# Input validation and checks
check_command() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}Error: $1 is not installed. Please install it before running the script.${NC}"
        exit 1
    fi
}

is_subnet() {
    local target=$1
    [[ "$target" == *"/"* ]]
}

# Scanning functions
run_sslscan() {
    local target=$1
    local output_file="results/sslscan/${target}_sslscan.txt"
    echo -e "${GREEN}Starting SSLScan on $target${NC}"
    sslscan --verbose "$target" | tee "$output_file"
    echo -e "${GREEN}SSLScan results saved to $output_file${NC}"
    echo -e "${GREEN}SSLScan on $target completed.${NC}"
    echo -e "\n--------------------------------\n"
}

run_ssh_audit() {
    local target=$1
    local output_file="results/sshaudit/${target}_sshaudit.txt"
    echo -e "${GREEN}Starting SSH-Audit on $target${NC}"
    ssh-audit -v "$target" | tee "$output_file"
    echo -e "${GREEN}SSH-audit results saved to $output_file${NC}"
    echo -e "${GREEN}SSH-Audit on $target completed.${NC}"
    echo -e "\n--------------------------------\n"
}

check_single_header() {
    local header=$1
    local headers=$2
    local url=$3
    local log_file=$4

    if echo "$headers" | grep -i "$header:" > /dev/null; then
        echo -e "${GREEN}${header} header found${NC}"
        echo "$url: ${header} header found" >> "$log_file"
    else
        echo -e "${RED}${header} header missing${NC}"
        echo "$url: ${header} header missing" >> "$log_file"
    fi
}

# Function to get the list of open ports on the host
get_open_ports() {
    local host=$1
    # Run nmap to get the list of open ports among 80,443,8080,8443
    local ports=$(nmap -Pn -p 80,443,8080,8443 --host-timeout 5s --max-retries 0 "$host" | awk '/^[0-9]+\/tcp/ && /open/ {split($1,a,"/"); print a[1]}')
    echo "$ports"
}

check_headers() {
    local url=$1

    echo -e "${GREEN}Starting CheckThatHeaders on $url${NC}"

    # Get open ports from 'get_open_ports' function
    local open_ports=$(get_open_ports "$url")

    # Check if there are open ports
    if [[ -z "$open_ports" ]]; then
        echo -e "${RED}No open ports found on $url. Skipping header checks.${NC}"
        echo -e "\n--------------------------------\n"
        return
    fi

    # For each open port, perform the header checks
    for port in $open_ports; do
        local log_file="results/checkthatheader/${url}_${port}_header_check.txt"
        mkdir -p "$(dirname "$log_file")"  # Ensure the directory exists

        echo -e "${GREEN}Fetching headers from $url:$port${NC}"
        # Fetch the headers and save to log file
        headers=$(wget -d --verbose --spider --server-response --timeout=10 --tries=1 "$url:$port" 2>&1 | tee "$log_file" | grep -i -E "Content-Security-Policy|Permissions-Policy|Referrer-Policy|X-Content-Type-Options|Strict-Transport-Security|X-Frame-Options")
        
        # Check for each header and log the result
        check_single_header "Content-Security-Policy" "$headers" "$url:$port" "$log_file"
        check_single_header "Permissions-Policy" "$headers" "$url:$port" "$log_file"
        check_single_header "Referrer-Policy" "$headers" "$url:$port" "$log_file"
        check_single_header "X-Content-Type-Options" "$headers" "$url:$port" "$log_file"
        check_single_header "Strict-Transport-Security" "$headers" "$url:$port" "$log_file"
        check_single_header "X-Frame-Options" "$headers" "$url:$port" "$log_file"
    done
    echo -e "${GREEN}Header checks for $url completed. Check the 'checkthatheader' folder for the output.${NC}"
    echo -e "\n--------------------------------\n"
}

scan_target() {
    local target=$1
    if is_subnet "$target"; then
        relay_from_tcp_scan "$target"
        if [[ -f "results/live_hosts.txt" ]]; then
            cat results/live_hosts.txt >> results/all_targets.txt
            while IFS= read -r live_host; do
                if [[ "$exclude_sslscan" != true ]]; then
                    run_sslscan "$live_host"
                fi
                if [[ "$exclude_sshaudit" != true ]]; then
                    run_ssh_audit "$live_host"
                fi
                if [[ "$exclude_checkheaders" != true ]]; then
                    check_headers "$live_host"
                fi
            done < results/live_hosts.txt
            rm results/live_hosts.txt
        fi
    else
        echo "$target" >> results/all_targets.txt
        if [[ "$exclude_sslscan" != true ]]; then
            run_sslscan "$target"
        fi
        if [[ "$exclude_sshaudit" != true ]]; then
            run_ssh_audit "$target"
        fi
        if [[ "$exclude_checkheaders" != true ]]; then
            check_headers "$target"
        fi
    fi
}

complete_all_scans() {
    if [[ "$exclude_sslscan" != true ]]; then
        echo -e "${BLUE}SSLScan, SSH-Audit, and CheckThatHeaders scans completed.${NC}"
        echo -e "\n--------------------------------\n"
        echo -e "\n"
    fi
}

# Metasploit scans
scan_rdp() {
    local targets_file=$1
    if [[ -s "$targets_file" ]]; then
        mkdir -p results/msfrdp  # Ensure the directory exists
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

            # Run msfconsole with resource script
            msfconsole -q -r "$resource_script"
            echo -e "${BLUE}RDP scan for $target_ip completed, results saved to $output_file${NC}"
            echo -e "\n--------------------------------\n"
        done < "$targets_file"
    else
        echo -e "${YELLOW}No RDP targets found. Skipping RDP Metasploit scan.${NC}"
        echo -e "\n--------------------------------\n"
    fi
}

scan_rpc() {
    local targets_file=$1
    if [[ -s "$targets_file" ]]; then
        mkdir -p results/msfrpc  # Ensure the directory exists
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

            # Run msfconsole with resource script
            msfconsole -q -r "$resource_script"
            echo -e "${BLUE}RPC scan for $target_ip completed, results saved to $output_file${NC}"
            echo -e "\n--------------------------------\n"
        done < "$targets_file"
    else
        echo -e "${YELLOW}No RPC targets found. Skipping RPC Metasploit scan.${NC}"
        echo -e "\n--------------------------------\n"
    fi
}

scan_oracle() {
    local targets_file=$1
    if [[ -s "$targets_file" ]]; then
        mkdir -p results/msforacletnscmd  # Ensure the directory exists
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
            # Run msfconsole with resource script
            msfconsole -q -r "$resource_script"
            echo -e "${BLUE}Oracle TNS Listener SID Enumeration scan for $target_ip completed, results saved to $output_file${NC}\n"
        done < "$targets_file"
    else
        echo -e "${YELLOW}No Oracle TNS Listener targets found. Skipping Oracle Metasploit scan.${NC}\n"
    fi
}

# Helper functions
relay_from_tcp_scan() {
    local subnet=$1
    echo -e "\n${YELLOW}Target is a subnet, starting the live hosts check.${NC}\n"
    echo -e "${GREEN}Running Nmap to get live hosts in subnet $subnet${NC}"
    nmap -sn "$subnet" -oG - | awk '/Up$/{print $2}' > results/live_hosts.txt
    echo -e "Found live hosts in $subnet:"
    cat results/live_hosts.txt
    echo -e "\n${BLUE}Live hosts check completed.${NC}\n"
}

# Display ASCII art on every run
display_ascii_art

# Variables to check if options are set
a_option_set=false
add_vulners=false
add_vuln=false
exclude_sslscan=false
exclude_sshaudit=false
exclude_checkheaders=false

# Option parsing
while getopts ":t:u:1234aNkh" opt; do
    case ${opt} in
        t ) targets_file=$OPTARG ;;
        u )
            # Check for multiple hosts, spaces, commas, or subnets
            if [[ "$OPTARG" == *","* || "$OPTARG" == *" "* || "$OPTARG" == *"/"* ]]; then
                echo -e "${RED}Error: -u option accepts only a single IP address or hostname without spaces, commas, or subnets.${NC}"
                exit 1
            fi
            single_target="$OPTARG"
            ;;
        1 ) add_vulners=true ;;
        2 ) add_vuln=true ;;
        3 )
            add_vuln=true
            add_vulners=true
            ;;
        4 ) firewall_evasion=true ;;
        a ) a_option_set=true ;;
        N ) add_nT4=true ;;
        k )
            exclude_sslscan=true
            exclude_sshaudit=true
            exclude_checkheaders=true
            ;;
        h ) display_help ;;
        \? ) echo -e "${RED}Invalid option: -$OPTARG${NC}" 1>&2; exit 1 ;;
        : ) echo -e "${RED}Invalid option: -$OPTARG requires an argument${NC}" 1>&2; exit 1 ;;
    esac
done
shift $((OPTIND -1))

# Set exclude_allports if -a is specified
if [[ "$a_option_set" = true ]]; then
    exclude_allports=true
fi

# Ensure only one target type is provided
if [[ -n "$targets_file" && -n "$single_target" ]]; then
    echo -e "${RED}Error: Cannot specify both a targets file (-t) and a single target (-u).${NC}"
    exit 1
fi

# Check if the targets file exists or the single target is specified
if [[ -n "$targets_file" && ! -f "$targets_file" ]]; then
    echo -e "${RED}Error: Targets file '$targets_file' not found!${NC}"
    exit 1
elif [[ -z "$targets_file" && -z "$single_target" ]]; then
    echo -e "${GREEN}Use the -h option for help.${NC}"
    exit 1
fi

# Check if required tools are installed
check_command "nmap"
check_command "crackmapexec"
check_command "ssh-audit"
check_command "sslscan"
check_command "wget"
check_command "dig"
check_command "ldapsearch"
check_command "msfconsole"
check_command "curl"
check_command "rpcclient"

# Directory setup
mkdir -p results  # Ensure the 'results' directory exists

# Only create directories for LDAP and DNS if they will be used later
# Initially, skip creating 'results/ldap_anonymous_bind' and 'results/dnssec'

# Conditionally create firewallevasion directory based on -4 option
if [[ "$firewall_evasion" = true ]]; then
    mkdir -p results/firewallevasion
fi

# Conditionally create other directories based on -k option
if [[ "$exclude_sslscan" != true ]]; then
    mkdir -p results/sslscan
fi

if [[ "$exclude_sshaudit" != true ]]; then
    mkdir -p results/sshaudit
fi

if [[ "$exclude_checkheaders" != true ]]; then
    mkdir -p results/checkthatheader
fi

# Define firewall evasion scripts
declare -A firewall_evasion_scripts=(
    ["Fragment Packets Result"]='nmap -f -v --reason -oN results/firewallevasion/fragmentpacketsresult.txt'
    ["MTU Result"]='nmap -mtu 16 -v --reason -oN results/firewallevasion/mturesult.txt'
    ["MAC Spoof Apple Result"]='nmap -sT -PO --spoof-mac Apple -Pn -v --reason -oN results/firewallevasion/macspoofappleresult.txt'
    ["MAC Spoof Cisco Result"]='nmap -sT -PO --spoof-mac Cisco -Pn -v --reason -oN results/firewallevasion/macspoofciscoresult.txt'
    ["MAC Spoof Microsoft Result"]='nmap -sT -PO --spoof-mac Microsoft -Pn -v --reason -oN results/firewallevasion/macspoofmicrosoftresult.txt'
    ["MAC Spoof Intel Result"]='nmap -sT -PO --spoof-mac Intel -Pn -v --reason -oN results/firewallevasion/macspoofintelresult.txt'
    ["MAC Spoof Samsung Result"]='nmap -sT -PO --spoof-mac Samsung -Pn -v --reason -oN results/firewallevasion/macspoofsamsungresult.txt'
    ["MAC Spoof Dell Result"]='nmap -sT -PO --spoof-mac Dell -Pn -v --reason -oN results/firewallevasion/macspoofdellresult.txt'
    ["MAC Spoof HP Result"]='nmap -sT -PO --spoof-mac HP -Pn -v --reason -oN results/firewallevasion/macspoofhpresult.txt'
    ["MAC Spoof Sony Result"]='nmap -sT -PO --spoof-mac Sony -Pn -v --reason -oN results/firewallevasion/macspoofsonyresult.txt'
    ["MAC Spoof Netgear Result"]='nmap -sT -PO --spoof-mac Netgear -Pn -v --reason -oN results/firewallevasion/macspoofnetgearresult.txt'
    ["MAC Spoof TP-Link Result"]='nmap -sT -PO --spoof-mac TP-Link -Pn -v --reason -oN results/firewallevasion/macspooftplinkresult.txt'
    ["MAC Spoof ASUS Result"]='nmap -sT -PO --spoof-mac ASUS -Pn -v --reason -oN results/firewallevasion/macspoofasusresult.txt'
    ["MAC Spoof Juniper Result"]='nmap -sT -PO --spoof-mac Juniper -Pn -v --reason -oN results/firewallevasion/macspoofjuniperresult.txt'
    ["MAC Spoof Broadcom Result"]='nmap -sT -PO --spoof-mac Broadcom -Pn -v --reason -oN results/firewallevasion/macspoofbroadcomresult.txt'
    ["MAC Spoof Qualcomm Result"]='nmap -sT -PO --spoof-mac Qualcomm -Pn -v --reason -oN results/firewallevasion/macspoofqualcommresult.txt'
    ["Bad Checksum Result"]='nmap --badsum -v --reason -oN results/firewallevasion/badchecksumresult.txt'
    ["Exotic Flag Result"]='nmap -sF -p1-100 -T4 -v --reason -oN results/firewallevasion/exoticflagresult.txt'
    ["Source Port Check Result"]='nmap -sSUC --script source-port -Pn -v --reason -oN results/firewallevasion/sourceportcheckresult.txt'
    ["Source Port Result"]='nmap -g -Pn -v --reason -oN results/firewallevasion/sourceportresult.txt'
    ["ICMP Echo Request Result"]='nmap -n -sn -PE -T4 -v --reason -oN results/firewallevasion/icpmechorequestresult.txt'
    ["Packet Trace Result"]='nmap -vv -n -sn -PE -T4 --packet-trace -v --reason -oN results/firewallevasion/packettracceresult.txt'
)

# Execute firewall evasion scans in order if selected
if [[ "$firewall_evasion" = true ]]; then
    echo -e "${GREEN}Starting Firewall Evasion Scans${NC}\n"
    ordered_firewall_evasion_scripts=(
        "Fragment Packets Result"
        "MTU Result"
        "MAC Spoof Apple Result"
        "MAC Spoof Cisco Result"
        "MAC Spoof Microsoft Result"
        "MAC Spoof Intel Result"
        "MAC Spoof Samsung Result"
        "MAC Spoof Dell Result"
        "MAC Spoof HP Result"
        "MAC Spoof Sony Result"
        "MAC Spoof Netgear Result"
        "MAC Spoof TP-Link Result"
        "MAC Spoof ASUS Result"
        "MAC Spoof Juniper Result"
        "MAC Spoof Broadcom Result"
        "MAC Spoof Qualcomm Result"
        "Bad Checksum Result"
        "Exotic Flag Result"
        "Source Port Check Result"
        "Source Port Result"
        "ICMP Echo Request Result"
        "Packet Trace Result"
    )

    for script_name in "${ordered_firewall_evasion_scripts[@]}"; do
        if [[ -n "$targets_file" ]]; then
            echo -e "${GREEN}Starting scan for ${script_name}.${NC}"
            eval "${firewall_evasion_scripts[$script_name]} -iL \"$targets_file\""
            echo -e "${GREEN}Completed ${script_name} scan.${NC}\n"
        elif [[ -n "$single_target" ]]; then
            echo -e "${GREEN}Starting scan for ${script_name}.${NC}"
            eval "${firewall_evasion_scripts[$script_name]} \"$single_target\""
            echo -e "${GREEN}Completed ${script_name} scan.${NC}\n"
        fi
    done

    echo -e "${BLUE}Firewall evasion scans completed.${NC}"
    exit 0
fi

# Define Nmap scripts
declare -A scripts=(
    ["SMB"]='-p 139,445 --script smb-security-mode,smb2-security-mode,smb-enum-users.nse,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010 -oN results/smbsec.txt -v'
    ["SSLCipher"]='--script ssl-enum-ciphers -p 443,1443,389,3389 -oN results/sslcipher.txt -v'
    ["HTTPSVN"]='--script http-svn-enum,http-svn-info -p 443 -oN results/httpsvnenum.txt -v'
    ["NetBIOS"]='-sU -sV -T4 --script nbstat -p137 -Pn -n -oN results/netbiosinfodis.txt -v'
    ["Oracle"]='--script oracle-tns-version,oracle-sid-brute -p 1521 -T4 -sV -oN results/oracle.txt -oG results/oracle.gnmap -v'
    ["NTP"]='-sU -sV --script ntp-monlist,ntp-info -p 123 -oN results/ntpservice.txt -v'
    ["SNMP"]='-sV --script snmp-brute -p161 -vvv -oN results/snmpinfodis.txt -v'
    ["LDAP"]='-n -sV --script ldap*,ldap-search,ldap-novell-getpass -p 389,636,3268,3269 -oN results/ldap.txt -oG results/ldap.gnmap -v'
    ["HTTP"]='-sV -p 80,81,443,8000,8080,8443 --script http-headers,http-iis-webdav-vuln,http-iis-short-name-brute,http-auth-finder,http-apache-server-status,http-traceroute,http-trace,http-vuln*,http-axis2-dir-traversal,http-cross-domain-policy --script-args http-cross-domain-policy.domain-lookup=true -oN results/http.txt -oG results/http.gnmap -v'
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
    ["TFTP"]='-n -Pn -sU -p69 -sV --script tftp-enum -oN results/tftp.txt -v'
    ["WildcardCertificate"]='--script ssl-cert -p443 -oN results/wildcardcert.txt -v'
    ["SMTP"]='--script smtp-commands,smtp-open-relay,smtp-enum-users -p 25,465,587 -oN results/smtp.txt -v'
    ["IPMI"]='-sU --script ipmi-brute,ipmi-cipher-zero -p 623 -oN results/ipmi.txt -v'
    ["IMAP"]='--script imap-brute,imap-ntlm-info -p 143,993 -oN results/imap.txt -v'
    ["IKE"]='-sU -sV --script ike-version -p 500 -oN results/ike.txt -v'
    ["AFP"]='-sS -sV --script afp-showmount,afp-ls -p 548 -oN results/afp.txt -v'
    ["Gopher"]='--script gopher-ls --script-args gopher-ls.maxfiles=100 -p 70 -oN results/gopher.txt -v'
    ["Kerberos"]='--script krb5-enum-users --script-args krb5-enum-users.realm='"'"'test'"'"' -p 88 -oN results/kerberos.txt -v'
    ["PJL"]='--script pjl-ready-message.nse --script-args '"'"'pjl_ready_message="pwn3d!"'"'"' -oN results/pjl.txt -v'
    ["Redis"]='--script redis-info,redis-brute -p 6379 -oN results/redis.txt -v'
    ["RealVNC"]='--script realvnc-auth-bypass -p 5900 -oN results/realvnc.txt -v'
    ["SIP"]='-sU --script sip-brute,sip-call-spoof,sip-enum-users --script-args '"'"'sip-enum-users.padding=4,sip-enum-users.minext=1000,sip-enum-users.maxext=9999'"'"' -p 5060 -oN results/sip.txt -v'
    ["TCP"]='-sC -sV -oN results/tcp.txt -oG results/tcp.gnmap -v --reason'
    ["UDP"]='-sC -sU -T4 -oN results/udp.txt -v --reason'
    ["AllPorts"]='-p- -T4 -oN results/allports.txt -v --reason'
)

# Specify the order in which the scripts should be executed
ordered_scripts=(
    "SMB"
    "SSLCipher"
    "HTTPSVN"
    "NetBIOS"
    "Oracle"
    "NTP"
    "SNMP"
    "LDAP"
    "HTTP"
    "Portmapper"
    "MySQL"
    "MSSQL"
    "SSH"
    "Telnet"
    "DNS"
    "Pop3"
    "NFS"
    "RDP"
    "RPC"
    "ApacheAJP"
    "FTP"
    "TFTP"
    "WildcardCertificate"
    "SMTP"
    "IPMI"
    "IMAP"
    "IKE"
    "AFP"
    "Gopher"
    "Kerberos"
    "PJL"
    "Redis"
    "RealVNC"
    "SIP"
    "TCP"
    "UDP"
    "AllPorts"
)

# Exclude UDP and All Ports scripts if -a is specified
if [[ "$exclude_allports" = true ]]; then
    echo -e "${YELLOW}Starting scans without 'UDP' and 'AllPorts' scripts.${NC}\n"
    ordered_scripts=($(printf "%s\n" "${ordered_scripts[@]}" | grep -v -E "^(UDP|AllPorts)$"))
fi

# Accumulate additional Nmap scripts based on options
additional_nmap_scripts=()

# Add vulners script if specified
if [[ "$add_vulners" = true ]]; then
    echo -e "${YELLOW}Starting scans with option -1 (vulners).${NC}\n"
    additional_nmap_scripts+=("vulners")
fi

# Add vuln script if specified
if [[ "$add_vuln" = true ]]; then
    echo -e "${YELLOW}Starting scans with option -2 (vuln).${NC}\n"
    additional_nmap_scripts+=("vuln")
fi

# Remove duplicate scripts
IFS=',' read -r -a unique_scripts <<< "$(printf "%s\n" "${additional_nmap_scripts[@]}" | sort -u | paste -sd, -)"

# Add the accumulated scripts to each Nmap script entry
if [[ -n "$unique_scripts" ]]; then
    for key in "${!scripts[@]}"; do
        if [[ "${scripts[$key]}" == *"--script "* ]]; then
            # Extract existing scripts after --script
            existing_scripts="${scripts[$key]#*--script }"
            # Prepend additional scripts
            scripts[$key]="--script $unique_scripts,$existing_scripts"
        fi
    done
fi

# Add -n -T4 to Nmap scripts if -N is specified
if [[ "$add_nT4" = true ]]; then
    echo -e "${YELLOW}Adding -n -T4 to accelerate associative array scans.${NC}\n"
    for key in "${!scripts[@]}"; do
        scripts[$key]="-n -T4 ${scripts[$key]}"
    done
fi

# -------------------- #
#    *** ADDITION ***  #
# -------------------- #

# Display the appropriate message based on the -k flag
if [[ "$exclude_sslscan" = true && "$exclude_sshaudit" = true && "$exclude_checkheaders" = true ]]; then
    echo -e "${YELLOW}Starting scans without sslscan, ssh-audit and checkthatheaders.${NC}\n"
fi

# -------------------- #
#    *** END ADD ***    #
# -------------------- #

# Main scanning loop
for script_name in "${ordered_scripts[@]}"; do
    # Skip if script_name is empty
    [[ -z "$script_name" ]] && continue

    # Check if script_name exists in scripts array
    if [[ -z "${scripts[$script_name]}" ]]; then
        echo -e "${RED}Warning: Script '$script_name' not found in scripts array.${NC}"
        continue
    fi

    script_args="${scripts[$script_name]}"
    if [[ -z "$script_args" ]]; then
        continue
    fi

    # Check if targets_file exists and is not empty before running nmap with -iL
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

echo -e "${BLUE}Associative scans completed, output files saved to results directory.${NC}"
echo -e "\n--------------------------------\n"

# Now process targets and run scanning functions
if [[ "$firewall_evasion" != true ]]; then
    # Display the message once before starting scans
    if [[ "$exclude_sslscan" != true || "$exclude_sshaudit" != true || "$exclude_checkheaders" != true ]]; then
        echo -e "${YELLOW}Starting SSLScan, SSH-Audit, and CheckThatHeaders.${NC}\n"
    fi

    if [[ -n "$targets_file" ]]; then
        while IFS= read -r target; do
            scan_target "$target"
        done < "$targets_file"
    elif [[ -n "$single_target" ]]; then
        scan_target "$single_target"
    fi
    # Call the function to display the overall completion message
    complete_all_scans
fi

# ----------------------------- #
#       METASPLOIT SCANS        #
# ----------------------------- #

# Extract RDP targets (port 3389) from rdp.gnmap
if [[ -f "results/rdp.gnmap" ]]; then
    echo -e "${YELLOW}Starting Metasploit Scan.${NC}"
    echo -e "\n${YELLOW}Extracting RDP (port 3389) open IPs from rdp.gnmap.${NC}"
    awk '/^Host: / && /Ports:.*3389\/open/ {print $2}' results/rdp.gnmap > results/rdp_targets.txt
else
    echo -e "\n${RED}rdp.gnmap not found. Skipping RDP target extraction.${NC}"
    touch results/rdp_targets.txt  # Create empty file to handle later
fi

# Extract RPC targets (port 135) from rpc.gnmap
if [[ -f "results/rpc.gnmap" ]]; then
    echo -e "${YELLOW}Extracting RPC (port 135) open IPs from rpc.gnmap.${NC}"
    awk '/^Host: / && /Ports:.*135\/open/ {print $2}' results/rpc.gnmap > results/rpc_targets.txt
else
    echo -e "\n${RED}rpc.gnmap not found. Skipping RPC target extraction.${NC}"
    touch results/rpc_targets.txt  # Create empty file to handle later
fi

# Extract Oracle TNS Listener targets (port 1521) from oracle.gnmap
if [[ -f "results/oracle.gnmap" ]]; then
    echo -e "${YELLOW}Extracting Oracle TNS Listener (port 1521) open IPs from oracle.gnmap.${NC}"
    awk '/^Host: / && /Ports:.*1521\/open/ {print $2}' results/oracle.gnmap > results/oracle_targets.txt
else
    echo -e "\n${RED}oracle.gnmap not found. Skipping Oracle target extraction.${NC}"
    touch results/oracle_targets.txt  # Create empty file to handle later
fi

# Perform Metasploit scans if targets are found
echo -e "\n${YELLOW}Starting Metasploit scans based on open RDP, RPC, and Oracle TNS Listener ports.${NC}\n"

# Scan RDP targets
scan_rdp "results/rdp_targets.txt"

# Scan RPC targets
scan_rpc "results/rpc_targets.txt"

# Scan Oracle TNS Listener targets
scan_oracle "results/oracle_targets.txt"

# ----------------------------- #
#      SCANS COMPLETED MESSAGE   #
# ----------------------------- #

echo -e "${BLUE}Metasploit Scans Completed.${NC}"
echo -e "\n--------------------------------\n"

# ------------------------------------------- #
#       DEFAULT IIS WEBPAGE DETECTION         #
# ------------------------------------------- #

found_iis=false

# Parse results/http.gnmap to find hosts with Microsoft-IIS in service/version
if [[ -f "results/http.gnmap" ]]; then
    echo -e "${YELLOW}Starting Default IIS Webpage scan.${NC}\n"
    echo -e "${YELLOW}Parsing HTTP Result to find hosts with Microsoft-IIS in Service/Version.${NC}"
    grep -i "Ports:" results/http.gnmap | grep -i "open" | grep -i "Microsoft-IIS" | while read -r line; do
        # Extract IP address
        ip=$(echo "$line" | awk '{print $2}')
        # Extract the Ports section
        ports_field=$(echo "$line" | sed 's/.*Ports: //')
        # Split the ports field by comma
        IFS=',' read -ra ports_array <<< "$ports_field"
        for port_info in "${ports_array[@]}"; do
            # Trim leading/trailing whitespace
            port_info=$(echo "$port_info" | xargs)
            # Split port_info by '/'
            IFS='/' read -ra port_fields <<< "$port_info"
            port_number="${port_fields[0]}"
            state="${port_fields[1]}"
            protocol="${port_fields[2]}"
            owner="${port_fields[3]}"
            service="${port_fields[4]}"
            version="${port_fields[5]}"
            # Combine service and version for matching
            service_version="$service $version"
            # Check if state is 'open' and service_version contains 'Microsoft-IIS'
            if [[ "$state" == "open" && "$service_version" == *"Microsoft-IIS"* ]]; then
                echo -e "${GREEN}Found Microsoft-IIS on $ip:$port_number via service/version.${NC}"
                # Create the directory if not already done
                if [[ "$found_iis" = false ]]; then
                    mkdir -p results/defaultiis
                    found_iis=true
                fi
                output_file="results/defaultiis/defaultiis_${ip}_${port_number}.txt"
                echo -e "${GREEN}Running curl on $ip:$port_number to get default IIS webpage.${NC}"
                curl -k -L "$ip:$port_number" -v 2>&1 | tee "$output_file"
                echo -e
                echo -e "${BLUE}Output saved to $output_file${NC}\n"
                echo -e "\n--------------------------------\n"
            fi
        done
    done
else
    echo -e "${RED}results/http.gnmap not found. Skipping Microsoft-IIS detection from gnmap.${NC}\n"
fi

# Parse results/http.txt to find hosts with Microsoft-IIS in Server header
if [[ -f "results/http.txt" ]]; then
    echo -e "${YELLOW}Parsing HTTP Result to find hosts with Microsoft-IIS in Server Header.${NC}"
    current_ip=""
    current_port=""
    while IFS= read -r line; do
        if [[ "$line" == "Nmap scan report for "* ]]; then
            current_ip=$(echo "$line" | awk '{print $5}')
            echo -e "Processing host $current_ip"
        elif [[ "$line" =~ ^[0-9]+/[a-z]+[[:space:]]+open ]]; then
            # This is a port line
            current_port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
            echo -e "${GREEN}Processing port $current_port on $current_ip${NC}"
        elif [[ "$line" =~ "Server: Microsoft-IIS" ]]; then
            echo -e "${GREEN}Found Microsoft-IIS on $current_ip:$current_port via Header${NC}"
            # Create the directory if not already done
            if [[ "$found_iis" = false ]]; then
                mkdir -p results/defaultiis
                found_iis=true
            fi
            output_file="results/defaultiis/defaultiis_${current_ip}_${current_port}.txt"
            echo -e "${GREEN}Running curl on $current_ip:$current_port to get default IIS webpage.${NC}"
            curl -k -L "$current_ip:$current_port" -v 2>&1 | tee "$output_file"
            echo -e
            echo -e "${BLUE}Output saved to $output_file${NC}\n"
        fi
    done < results/http.txt
else
    echo -e "${RED}results/http.txt not found. Skipping Microsoft-IIS detection from http.txt.${NC}\n"
fi

if [[ "$found_iis" = false ]]; then
    echo -e "${YELLOW}No hosts with Microsoft-IIS found.${NC}\n"
else
    echo -e "${BLUE}Default IIS Webpage Detection completed.${NC}"
    echo -e "\n--------------------------------\n"
fi

# ----------------------------- #
#    UNAUTHENTICATED RPC SCAN   #
# ----------------------------- #

if [[ -s "results/rpc_targets.txt" ]]; then
    echo -e "${YELLOW}Starting Unauthenticated RPC scan.${NC}\n"
    mkdir -p results/unauthrpc
    while IFS= read -r target_ip; do
        echo -e "${GREEN}Attempting Unauthenticated RPC connection to $target_ip${NC}"
        output_file="results/unauthrpc/unauthrpc_${target_ip}.txt"
        # Use rpcclient to attempt connection
        rpcclient -U "" -N "$target_ip" -c 'enumprivs' 2>&1 | tee "$output_file"
        # Check if connection was successful
        if grep -q -E "Cannot connect|NT_STATUS|failed|Connection to host failed" "$output_file"; then
            echo -e "${RED}Connection to $target_ip failed or authentication required. Skipping scan.${NC}"
            rm "$output_file"
        else
            echo -e "${BLUE}Unauthenticated RPC connection to $target_ip successful. Output saved to $output_file${NC}"
            echo -e "\n--------------------------------\n"
        fi
    done < results/rpc_targets.txt
    echo -e "\n${BLUE}Unauthenticated RPC scan completed.${NC}"
    echo -e "\n--------------------------------\n"
else
    echo -e "${YELLOW}No RPC targets found. Skipping Unauthenticated RPC scan.${NC}"
    echo -e "\n--------------------------------\n"
fi

# ----------------------------- #
#       LDAP ANONYMOUS BIND     #
# ----------------------------- #

echo -e "${YELLOW}Starting LDAP Anonymous Bind scan.${NC}\n"
if [[ -f "results/ldap.gnmap" ]]; then
    # Parse ldap.gnmap to extract IPs with LDAP ports open (389,636,3268,3269)
    ldap_ports="389|636|3268|3269"
    awk '/^Host: / && /Ports:.*('"$ldap_ports"')\/open/ {print $2}' results/ldap.gnmap > results/ldap_open_ports.txt

    if [[ -s "results/ldap_open_ports.txt" ]]; then
        echo -e "${GREEN}LDAP ports open found, starting LDAP Anonymous Bind scan.${NC}\n"
        mkdir -p results/ldap_anonymous_bind

        while read -r ip; do
            echo -e "${GREEN}Running LDAP Anonymous Bind scan on $ip${NC}"
            output_file="results/ldap_anonymous_bind/${ip}_ldap_anonymous_bind.txt"
            ldapsearch -v -x -s base -b '' "(objectClass=*)" "*" + -H ldap://$ip | tee "$output_file"
            echo -e "${BLUE}LDAP Anonymous Bind scan for $ip completed and saved to $output_file${NC}\n"
        done < results/ldap_open_ports.txt

        # Added completed message
        echo -e "${BLUE}LDAP Anonymous Bind Scan Completed.${NC}"
        echo -e "\n--------------------------------\n"
    else
        echo -e "${YELLOW}No LDAP ports open found. Skipping LDAP Anonymous Bind scan.${NC}"
        echo -e "\n--------------------------------\n"
    fi
    rm -f results/ldap_open_ports.txt
else
    echo -e "${RED}ldap.gnmap not found. Skipping LDAP Anonymous Bind scan.${NC}"
    echo -e "\n--------------------------------\n"
fi

# ----------------------------- #
#      DNS VULNERABILITIES      #
# ----------------------------- #

echo -e "${YELLOW}Starting DNS Vulnerabilities scan using 'dig +dnssec'.${NC}\n"
if [[ -f "results/dnsvuln.gnmap" ]]; then
    # Parse dnsvuln.gnmap to extract IPs with port 53 open
    ips_with_port_53_open=$(awk '/^Host: / && /Ports:.*53\/open/{print $2}' results/dnsvuln.gnmap)

    if [[ -n "$ips_with_port_53_open" ]]; then
        echo -e "${YELLOW}Port 53 found open on the following hosts:${NC}"
        echo "$ips_with_port_53_open"

        # Create directory to save dig scans
        mkdir -p results/dnssec

        # For each IP, run 'dig +dnssec <IP>' and save output
        for ip in $ips_with_port_53_open; do
            echo -e "\n${GREEN}Running 'dig +dnssec' on $ip${NC}"
            output_file="results/dnssec/${ip}_dnssec_test.txt"
            dig +dnssec "$ip" | tee "$output_file"
            echo -e "${BLUE}DNSSec scan for $ip completed and saved to $output_file${NC}"
            echo -e "\n--------------------------------\n"
        done
    else
        echo -e "${YELLOW}No hosts found with port 53 open. Skipping DNSSec scan.${NC}"
        echo -e "\n--------------------------------\n"
    fi
else
    echo -e "${RED}dnsvuln.gnmap not found. Skipping DNSSec scan.${NC}\n"
    echo -e "\n--------------------------------\n"
fi

# Add the completion message
echo -e "${BLUE}DNS Vulnerabilities Scan Completed.${NC}\n"

# ----------------------------- #
#       CRACKMAPEXEC SCAN       #
# ----------------------------- #

# Run CrackMapExec command
echo -e "${YELLOW}Starting CrackMapExec for SMBv1 detection.${NC}\n"

# Determine target list
if [[ -n "$targets_file" ]]; then
    target_list="$targets_file"
elif [[ -n "$single_target" ]]; then
    target_list="$single_target"
else
    echo -e "${RED}No valid target specified for CrackMapExec.${NC}"
    target_list=""
fi

if [[ -n "$target_list" ]]; then
    crackmapexec smb -p 445 "$target_list" | grep SMBv1:True > results/smbv1.txt

    # Check if smbv1.txt has any content
    if [[ -s "results/smbv1.txt" ]]; then
        echo -e "${GREEN}CrackMapExec found SMBv1 enabled on the following IPs:${NC}"
        cat results/smbv1.txt
    else
        echo -e "${RED}No SMBv1 enabled hosts found.${NC}\n"
    fi
    echo -e "${BLUE}CrackMapExec SMBv1 detection completed.${NC}"
    echo -e "\n--------------------------------\n"
else
    echo -e "${RED}No targets provided for CrackMapExec. Skipping SMBv1 detection.${NC}"
    echo -e "\n--------------------------------\n"
fi

echo -e "${GREEN}Overall scans completed. Check the 'results' directory for outputs. Happy Hacking!${NC}"
