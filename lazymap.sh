#!/bin/bash
# Title: lazymap
# Description: Lazymap is a single command-line tool made for network penetration testing. It is composed of multiple selected NMAP scripts, sslscan, ssh-audit, selected metasploit modules, and an HTTP header security checker.
# Author: Evan Ricafort - https://evanricafort.com | X: @evanricafort

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Display the Lazymap ascii art banner
function display_ascii_art() {
    echo -e "[..            [.       [....... [..[..      [..[..       [..      [.       [.......  "
    echo -e "[..           [. ..            [..   [..    [.. [. [..   [...     [. ..     [..    [.."
    echo -e "[..          [.  [..          [..     [.. [..   [.. [.. [ [..    [.  [..    [..    [.."
    echo -e "[..         [..   [..       [..         [..     [..  [..  [..   [..   [..   [.......  "
    echo -e "[..        [...... [..     [..          [..     [..   [.  [..  [...... [..  [..       "
    echo -e "[..       [..       [..  [..            [..     [..       [.. [..       [.. [..       "
    echo -e "[........[..         [..[...........    [..     [..       [..[..         [..[..  v0.5 "
    echo ""
}

# Display ASCII art on every run
display_ascii_art

# Function to display help message
function display_help() {
    echo -e "${GREEN}Name: Lazymap (Project0x01)${NC}"
    echo -e "${YELLOW}Author: Evan Ricafort (X - @evanricafort | Portfolio - https://evanricafort.com)${NC}"
    echo -e "${GREEN}Description: Lazymap is a single command-line tool made for network penetration testing. It is composed of multiple selected NMAP scripts, sslscan, ssh-audit, selected metasploit modules, and an HTTP header security checker.${NC}"
    echo ""
    echo -e "${GREEN}--Usage--${NC}"
    echo ""
    echo -e "${GREEN}- ./lazymap.sh -u host [Single Host] or ./lazymap.sh -t hosts.txt [Multiple Hosts]${NC}"
    echo -e "${GREEN}- Additional Options: Insert additional scripts with option ${YELLOW}-1${NC} ${GREEN}for [vulners],${NC} ${YELLOW}-2${NC} ${GREEN}for [vuln],${NC} ${YELLOW}-3${NC} ${GREEN}for both [vulners & vuln] NSE scripts,${NC} ${YELLOW}-4${NC} ${GREEN}for Firewall Evasion Scan, and${NC} ${YELLOW}-a${NC} ${GREEN}if you want to exclude the all ports scan.${NC}"
    echo ""
    echo -e "${GREEN}- Reminder: Option -3 may take some time to finish if you have multiple targets.${NC}"
    echo ""
    echo -e "${GREEN}- Note: Run in sudo mode to execute NMAP scripts related to UDP scan.${NC}"
    exit 0
}

# Function to check if a command is installed
function check_command() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}Error: $1 is not installed. Please install it before running the script.${NC}"
        exit 1
    fi
}

# Check if required tools are installed
check_command "nmap"
check_command "crackmapexec"
check_command "ssh-audit"
check_command "sslscan"
check_command "wget"

# Variables to check if options are set
a_option_set=false

# Check if options are provided
while getopts ":t:u:1234ah" opt; do
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
        3 ) add_vuln_vulners=true ;;
        4 ) firewall_evasion=true ;;
        a ) a_option_set=true ;;
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

# Function to check if the target is a subnet or an individual IP
function is_subnet() {
    local target=$1
    if [[ "$target" == *"/"* ]]; then
        return 0  # It's a subnet
    else
        return 1  # It's an individual IP
    fi
}

# Function to relay targets from TCP scan results if the target is a subnet
function relay_from_tcp_scan() {
    local subnet=$1
    echo -e "\n"
    echo -e "${YELLOW}Target is a subnet, starting the live hosts check.${NC}"
    echo -e "\n"
    echo -e "${GREEN}Running Nmap to get live hosts in subnet $subnet${NC}"
    nmap -sn "$subnet" -oG - | awk '/Up$/{print $2}' > results/live_hosts.txt
    echo -e "Found live hosts in $subnet:"
    cat results/live_hosts.txt
    echo -e
    echo -e "${BLUE}Live hosts check completed.${NC}"
    echo -e "\n"
}

# SSLScan function with individual file output
function run_sslscan() {
    local target=$1
    local output_file="results/sslscan/${target}_sslscan.txt"
    echo -e "\n"
    echo -e "${GREEN}Starting SSLScan on $target${NC}"
    sslscan --verbose "$target" | tee "$output_file"
    echo -e "${GREEN}SSLScan results saved to $output_file${NC}"
    echo -e "${GREEN}SSLScan on $target completed.${NC}"
    echo -e "\n"
}

# SSH-audit function with individual file output
function run_ssh_audit() {
    local target=$1
    local output_file="results/sshaudit/${target}_sshaudit.txt"
    echo -e "${GREEN}Starting SSH-Audit on $target${NC}"
    ssh-audit -v "$target" | tee "$output_file"
    echo -e "${GREEN}SSH-audit results saved to $output_file${NC}"
    echo -e "${GREEN}SSH-Audit on $target completed.${NC}"
    echo -e "\n"
}

# Function to scan RDP using Metasploit
function scan_rdp() {
    local targets_file=$1
    echo -e "${GREEN}Checking for RDP (Remote Desktop Protocol).${NC}"
    msfconsole -q -x "use auxiliary/scanner/rdp/rdp_scanner;
                      set rhosts file:$targets_file;
                      spool results/msf_rdp.txt;
                      run;
                      spool off;
                      exit"
    echo -e "${BLUE}RDP scan completed, results saved to results/msf_rdp.txt${NC}"
    echo -e "\n"
    echo -e "\n"
}

# Function to scan for Exposed RPC using Metasploit
function scan_rpc() {
    local targets_file=$1
    echo -e "${GREEN}Checking for RPC (Remote Procedure Call).${NC}"
    msfconsole -q -x "use auxiliary/scanner/dcerpc/endpoint_mapper;
                      set rhosts file:$targets_file;
                      spool results/msf_rpc.txt;
                      run;
                      spool off;
                      exit"
    echo -e "${BLUE}RPC scan completed, results saved to results/msf_rpc.txt${NC}"
    echo -e "\n"
    echo -e "\n"
}

# Function to check a single header
function check_single_header() {
    local header=$1
    local headers=$2
    local url=$3

    if echo "$headers" | grep -i "$header:" > /dev/null; then
        echo -e "${GREEN}${header} header found${NC}"
        echo "$url: ${header} header found" >> "$log_file"
    else
        echo -e "${RED}${header} header missing${NC}"
        echo "$url: ${header} header missing" >> "$log_file"
    fi
}

# Header checking function for both HTTP and HTTPS
function check_headers() {
    local url=$1
    local log_file="results/checkthatheader/${url}_header_check.txt"

    mkdir -p "$(dirname "$log_file")"  # Ensure the directory exists

    echo -e "${GREEN}Starting CheckThatHeaders on $url${NC}"

    # Fetch headers for both HTTP and HTTPS and log to file
    for port in 80 443 8443 8080; do
        headers=$(wget -d --verbose --spider --server-response --timeout=10 --tries=1 "$url:$port" 2>&1 | tee -a "$log_file" | grep -i -e "Content-Security-Policy" -e "Permissions-Policy" -e "Referrer-Policy" -e "X-Content-Type-Options" -e "Strict-Transport-Security" -e "X-Frame-Options")
        
        # Check for each header and log the result
        check_single_header "Content-Security-Policy" "$headers" "$url:$port"
        check_single_header "Permissions-Policy" "$headers" "$url:$port"
        check_single_header "Referrer-Policy" "$headers" "$url:$port"
        check_single_header "X-Content-Type-Options" "$headers" "$url:$port"
        check_single_header "Strict-Transport-Security" "$headers" "$url:$port"
        check_single_header "X-Frame-Options" "$headers" "$url:$port"
    done
    echo -e "${GREEN}Header checks for $url completed, check the checkthatheader folder for the output.${NC}"
    echo -e "\n"
}

# Function to scan a target, considering whether it is in a subnet
function scan_target() {
    local target=$1
    if is_subnet "$target"; then
        relay_from_tcp_scan "$target"
        echo -e "${YELLOW}Starting SSLScan, SSH-Audit, and CheckThatHeaders.${NC}"
        if [[ -f "results/live_hosts.txt" ]]; then
            cat results/live_hosts.txt >> results/all_targets.txt
            while IFS= read -r live_host; do
                run_sslscan "$live_host"
                run_ssh_audit "$live_host"
                check_headers "$live_host"
            done < results/live_hosts.txt
            rm results/live_hosts.txt
        fi
    else
        echo "$target" >> results/all_targets.txt
        echo -e "${YELLOW}Starting SSLScan, SSH-Audit, and CheckThatHeaders.${NC}"
        run_sslscan "$target"
        run_ssh_audit "$target"
        check_headers "$target"
    fi
}

# Function to handle the completion message for all SSLScan, SSH-Audit, and CheckThatHeaders scans
function complete_all_scans() {
    echo -e "${BLUE}SSLScan, SSH-Audit, and CheckThatHeaders scans completed.${NC}"
}

# Directory setup
mkdir -p results results/sslscan results/sshaudit results/checkthatheader results/firewallevasion

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
    ["Source Port Check Result"]='nmap -sS -v -v -Pn -v --reason -oN results/firewallevasion/sourceportcheckresult.txt'
    ["Source Port Result"]='nmap -g -Pn -v --reason -oN results/firewallevasion/sourceportresult.txt'
    ["ICMP Echo Request Result"]='nmap -n -sn -PE -T4 -v --reason -oN results/firewallevasion/icpmechorequestresult.txt'
    ["Packet Trace Result"]='nmap -vv -n -sn -PE -T4 --packet-trace -v --reason -oN results/firewallevasion/packettracceresult.txt'
)

# Execute firewall evasion scans in order if selected
if [[ "$firewall_evasion" = true ]]; then
    echo -e "${GREEN}Starting Firewall Evasion Scans${NC}"
    echo -e "\n"
    # Define ordered execution sequence for firewall evasion scripts
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
            ${firewall_evasion_scripts[$script_name]} -iL "$targets_file"
            echo -e "${GREEN}Completed ${script_name} scan.${NC}"
            echo -e "\n"
        elif [[ -n "$single_target" ]]; then
            echo -e "${GREEN}Starting scan for ${script_name}.${NC}"
            ${firewall_evasion_scripts[$script_name]} "$single_target"
            echo -e "${GREEN}Completed ${script_name} scan.${NC}"
            echo -e "\n"
        fi
    done
    
    echo -e "${BLUE}Firewall evasion scans completed.${NC}"
    exit 0
fi

# Define associative array for scripts
declare -A scripts=(
    ["SMB Security"]='-p 139,445 --script smb-security-mode,smb2-security-mode,smb-enum-users.nse,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010 -oN results/smbsec.txt -v'
    ["SSL Cipher"]='--script ssl-enum-ciphers -p 443,1443,389,3389 -oN results/sslcipher.txt -v'
    ["HTTP SVN"]='--script http-svn-enum,http-svn-info -p 443 -oN results/httpsvnenum.txt -v'
    ["NetBIOS Information Disclosure"]='-sU -sV -T4 --script nbstat -p137 -Pn -n -oN results/netbiosinfodis.txt -v'
    ["Oracle TNS Version"]='--script oracle-tns-version -p 1521 -T4 -sV -oN results/oracletnsversion.txt -v'
    ["Oracle SID Bruteforce"]='--script oracle-sid-brute -p 1521 -T4 -sV -oN results/oraclesidbrute.txt -v'
    ["NTP Service"]='-sU -sV --script ntp-monlist,ntp-info -p 123 -oN results/ntpservice.txt -v'
    ["SNMP Information Disclosure"]='-sV --script snmp-brute -p161 -vvv -oN results/snmpinfodis.txt -v'
    ["LDAP"]='-n -sV --script ldap*,ldap-search,ldap-novell-getpass -p 389,636,3268,3269 -oN results/ldap.txt -v'
    ["HTTP"]='-p 80,8080 --script http-iis-webdav-vuln,http-iis-short-name-brute,http-auth-finder,http-apache-server-status,http-traceroute,http-trace,http-vuln*,http-axis2-dir-traversal,http-cross-domain-policy --script-args http-cross-domain-policy.domain-lookup=true -oN results/http.txt -v'
    ["Portmapper"]='-sSUC --script nfs-showmount -p111 -oN results/portmapper111.txt -v'
    ["MySQL"]='-sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -oN results/mysql.txt -v'
    ["MSSQL"]='--script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes,broadcast-ms-sql-discover --script-args newtargets,mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 -oN results/mssql.txt -v'
    ["SSH"]='-p22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods --script-args ssh_hostkey=full,ssh.user=root -oN results/ssh.txt -v'
    ["Telnet Service"]='-n -sV -Pn --script telnet-brute,telnet-encryption,lu-enum,cics-info --script-args cics-info.user=test,cics-info.pass=test,cics-info.cemt='ZEMT',cics-info.trans=CICA -p 23 -oN results/telnetservice.txt -v'
    ["DNS"]='-n --script default,dns-fuzz,dns-brute,dns-cache-snoop -p 53 -oN results/dnsvuln.txt -v'
    ["Pop3"]='--script pop3-capabilities,pop3-ntlm-info -sV -p 110 -oN results/pop3.txt -v'
    ["NFS"]='--script nfs-ls,nfs-showmount,nfs-statfs -p 2049 -oN results/nfs.txt -v'
    ["RDP Check"]='--script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info -p 3389 -T4 -oN results/rdpscript.txt -v'
    ["Apache AJP"]='-sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 -oN results/apacheajp.txt -v'
    ["FTP"]='--script ftp-anon --script-args ftp-anon.maxlist=-1 -p 21 -oN results/ftp.txt -v'
    ["TFTP"]='-n -Pn -sU -p69 -sV --script tftp-enum -oN results/tftp.txt -v'
    ["Wildcard Certificate"]='--script ssl-cert -p443 -oN results/wildcardcert.txt -v'
    ["SMTP"]='--script smtp-commands,smtp-open-relay,smtp-enum-users -p 25,465,587 -oN results/smtp.txt -v'
    ["IPMI"]='-sU --script ipmi-brute,ipmi-cipher-zero -p 623 -oN results/ipmi.txt -v'
    ["IMAP"]='--script imap-brute,imap-ntlm-info -p 143,993 -oN results/imap.txt -v'
    ["IKE"]='-sU -sV --script ike-version -p 500 -oN results/ike.txt -v'
    ["AFP"]='-sS -sV --script afp-showmount,afp-ls -p 548 -oN results/afp.txt -v'
    ["Broadcast DNS"]='--script broadcast-dns-service-discovery -oN results/broadcastdns.txt -v'
    ["Broadcast Listener"]='--script broadcast-listener -e eth0 -oN results/broadcastlistener.txt -v'
    ["Broadcast Jenkins"]='--script broadcast-jenkins-discover --script-args timeout=15s -oN results/broadcastjenkins.txt -v'
    ["Broadcast UPNP"]='-sV --script broadcast-upnp-info -oN results/broadcastupnp.txt -v'
    ["Gopher"]='--script gopher-ls --script-args gopher-ls.maxfiles=100 -p 70 -oN results/gopher.txt -v'
    ["Kerberos"]='--script krb5-enum-users --script-args krb5-enum-users.realm='test' -p 88 -oN results/kerberos.txt -v'
    ["PJL"]='--script pjl-ready-message.nse --script-args 'pjl_ready_message="pwn3d!"' -oN results/pjl.txt -v'
    ["Redis"]='--script redis-info,redis-brute -p 6379 -oN results/redis.txt -v'
    ["RealVNC"]='--script realvnc-auth-bypass -p 5900 -oN results/realvnc.txt -v'
    ["SIP"]='-sU --script sip-brute,sip-call-spoof,sip-enum-users --script-args 'sip-enum-users.padding=4,sip-enum-users.minext=1000,sip-enum-users.maxext=9999' -p 5060 -oN results/sip.txt -v'
    ["TCP"]='-sC -sV -oN results/tcp.txt -v --reason'
    ["UDP"]='-sC -sU -T4 -oN results/udp.txt -v --reason'
    ["All Ports"]='-p- -T4 -oN results/allports.txt -v --reason'
)

# Specify the order in which the scripts should be executed
      ordered_scripts=(
          "SMB Security"
          "SSL Cipher"
          "HTTP SVN"
          "NetBIOS Information Disclosure"
          "Oracle TNS Version"
          "Oracle SID Bruteforce"
          "NTP Service"
          "SNMP Information Disclosure"
          "LDAP"
          "HTTP"
          "Portmapper"
          "MySQL"
          "MSSQL"
          "SSH"
          "Telnet Service"
          "DNS"
          "Pop3"
          "NFS"
          "RDP Check"
          "Apache AJP"
          "FTP"
          "TFTP"
          "Wildcard Certificate"
          "SMTP"
          "IPMI"
          "IMAP"
          "IKE"
          "AFP"
          "Broadcast DNS"
          "Broadcast Listener"
          "Broadcast Jenkins"
          "Broadcast UPNP"
          "Gopher"
          "Kerberos"
          "PJL"
          "Redis"
          "RealVNC"
          "SIP"
          "TCP"
          "UDP"
          "All Ports"
)

# Exclude UDP and All Ports scripts if -a is specified
if [[ "$exclude_allports" = true ]]; then
    echo -e "${YELLOW}Starting associative array scans without 'UDP' and 'All Ports' scripts.${NC}"
    echo -e
    # Remove 'UDP' and 'All Ports' from ordered_scripts
    ordered_scripts_tmp=()
    for script in "${ordered_scripts[@]}"; do
        if [[ "$script" != "UDP" && "$script" != "All Ports" ]]; then
            ordered_scripts_tmp+=("$script")
        fi
    done
    ordered_scripts=("${ordered_scripts_tmp[@]}")
fi

# Add vulners script if specified
if [[ "$add_vulners" = true ]]; then
    echo -e "${YELLOW}Starting associative array scans with option -1 (vulners).${NC}"
    echo -e
    for key in "${!scripts[@]}"; do
        scripts[$key]="${scripts[$key]/--script /--script vulners,}"
    done
fi

# Add vuln script if specified
if [[ "$add_vuln" = true ]]; then
    echo -e "${YELLOW}Starting associative array scans with option -2 (vuln).${NC}"
    echo -e
    for key in "${!scripts[@]}"; do
        scripts[$key]="${scripts[$key]/--script /--script vuln,}"
    done
fi

# Add vuln and vulners script if specified
if [[ "$add_vuln_vulners" = true ]]; then
    echo -e "${YELLOW}Starting associative array scans with option -3 (vuln and vulners).${NC}"
    echo -e
    for key in "${!scripts[@]}"; do
        scripts[$key]="${scripts[$key]/--script /--script vuln,vulners,}"
    done
fi

# Loop through each script and display Start/End message
for script_name in "${ordered_scripts[@]}"; do
    if [[ -z "$script_name" ]]; then
        continue
    fi
    script_args="${scripts[$script_name]}"
    if [[ -z "$script_args" ]]; then
        echo -e "${RED}Error: Script '$script_name' not found in scripts array.${NC}"
        continue
    fi
    if [[ -n "$targets_file" ]]; then
        echo -e "${GREEN}Starting ${script_name} scan.${NC}"
        nmap $script_args -iL "$targets_file"
        echo -e "${GREEN}Completed ${script_name} scan.${NC}"
        echo -e "\n"
    elif [[ -n "$single_target" ]]; then
        echo -e "${GREEN}Starting ${script_name} scan.${NC}"
        nmap $script_args "$single_target"
        echo -e "${GREEN}Completed ${script_name} scan.${NC}"
        echo -e "\n\n"
    fi
done

echo -e "${BLUE}Associative scans completed, output files saved to results directory.${NC}"
echo -e "\n"

# Main scan logic for single or multiple targets
if [[ -n "$single_target" ]]; then
    scan_target "$single_target"
elif [[ -n "$targets_file" ]]; then
    while IFS= read -r target; do
        scan_target "$target"
    done < "$targets_file"
fi

# Call the function to display the overall completion message
complete_all_scans

# After the main scan logic, run scan_rdp, scan_rpc, and the CrackMapExec command
if [[ -n "$targets_file" ]]; then
    if [[ -s "$targets_file" ]]; then
        echo -e "\n"
        echo -e "${YELLOW}Starting Metasploit Console."
        echo -e "\n"
        scan_rdp "$targets_file"
        scan_rpc "$targets_file"
        # Run CrackMapExec command
        echo -e "\n"
        echo -e "${YELLOW}Starting crackmapexec for SMBv1 detection."
        echo -e "\n"
        crackmapexec smb -p 445 "$targets_file" | grep SMBv1:True > results/smbv1.txt
        echo -e "\n"
        echo -e "${BLUE}CrackMapExec SMBv1 detection completed.${NC}"
        echo -e "\n"
    else
        echo -e "${RED}Error: Targets file '$targets_file' is empty!${NC}"
    fi
elif [[ -n "$single_target" ]]; then
    echo -e "\n"
    echo -e "${YELLOW}Starting Metasploit Console..."
    echo -e "\n"
    echo "$single_target" > single_target.txt
    scan_rdp "single_target.txt"
    scan_rpc "single_target.txt"
    # Run CrackMapExec command
    echo -e "\n"
    echo -e "${YELLOW}Starting crackmapexec for SMBv1 detection."
    echo -e "\n"
    crackmapexec smb -p 445 "$single_target" | grep SMBv1:True > results/smbv1.txt
    echo -e "\n"
    echo -e "${BLUE}CrackMapExec SMBv1 detection completed.${NC}"
    echo -e "\n"
    rm single_target.txt
fi

echo -e "${GREEN}All scans completed, check the results directory for outputs. Happy Hacking!${NC}"
