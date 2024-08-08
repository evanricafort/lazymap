#!/bin/bash
# Title: lazymap
# Description: A single command-line tool to execute multiple NMAP script for network penetration testing that will scan and detect security issues on common ports.
# Author: Evan Ricafort - https://evanricafort.com | X: @evanricafort
# Additional Information: Added crackmapexec to scan and detect SMBv1.

# Function to check for script completion
function scan_complete() {
  grep "Nmap scan report for" "$1" &>/dev/null
  if [[ $? -eq 0 ]]; then
    echo "Scan completed for: $(basename "$1") (target: $1)"
  fi
}

# Check if options are provided
while getopts ":t:u:1234" opt; do
  case ${opt} in
    t )
      targets_file=$OPTARG
      ;;
    u )
      single_target=$OPTARG
      ;;
    1 )
      add_vulners=true
      ;;
    2 )
      add_vuln=true
      ;;
    3 )
      add_vuln_vulners=true
      ;;
    4 )
      firewall_evasion=true
      ;;
    \? )
      echo "Invalid option: -$OPTARG" 1>&2
      exit 1
      ;;
    : )
      echo "Invalid option: -$OPTARG requires an argument" 1>&2
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

# Ensure only one target type is provided
if [[ -n "$targets_file" && -n "$single_target" ]]; then
  echo "Error: Cannot specify both a targets file (-t) and a single target (-u)."
  exit 1
fi

# Check if the targets file exists or the single target is specified
if [[ -n "$targets_file" && ! -f "$targets_file" ]]; then
  echo "Error: Targets file '$targets_file' not found!"
  exit 1
elif [[ -z "$targets_file" && -z "$single_target" ]]; then
  echo "Error: No targets specified!"
  echo "Usage: ./lazymap.sh -u target [Single Host] or ./lazymap.sh -t multipletarget.txt [Multiple Hosts]"
  echo "Additional Options: Insert additional scripts with -1 for [vulners], -2 for [vuln], -3 for both [vulners & vuln] NSE scripts and -4 for Firewall Evasion Scan."
  echo "Reminder: Option -3 may take some time to finish if you have multiple targets."
  exit 1
fi

# Define firewall evasion scripts
declare -A firewall_evasion_scripts=(
  ["fe_fragmentpacketsresult.txt"]='nmap -f -v --reason -oN results/firewarllevasion/fe_fragmentpacketsresult.txt'
  ["fe_mturesult.txt"]='nmap -mtu 16 -v --reason -oN results/firewarllevasion/fe_mturesult.txt'
  ["fe_macspoofappleresult.txt"]='nmap -sT -PO --spoof-mac Apple -Pn -v --reason -oN results/firewarllevasion/fe_macspoofappleresult.txt'
  ["fe_macspoofciscoresult.txt"]='nmap -sT -PO --spoof-mac Cisco -Pn -v --reason -oN results/firewarllevasion/fe_macspoofciscoresult.txt'
  ["fe_macspoofmicrosoftresult.txt"]='nmap -sT -PO --spoof-mac Microsoft -Pn -v --reason -oN results/firewarllevasion/fe_macspoofmicrosoftresult.txt'
  ["fe_macspoofintelresult.txt"]='nmap -sT -PO --spoof-mac Intel -Pn -v --reason -oN results/firewarllevasion/fe_macspoofintelresult.txt'
  ["fe_macspoofsamsungresult.txt"]='nmap -sT -PO --spoof-mac Samsung -Pn -v --reason -oN results/firewarllevasion/fe_macspoofsamsungresult.txt'
  ["fe_macspoofdellresult.txt"]='nmap -sT -PO --spoof-mac Dell -Pn -v --reason -oN results/firewarllevasion/fe_macspoofdellresult.txt'
  ["fe_macspoofhpresult.txt"]='nmap -sT -PO --spoof-mac HP -Pn -v --reason -oN results/firewarllevasion/fe_macspoofhpresult.txt'
  ["fe_macspoofsonyresult.txt"]='nmap -sT -PO --spoof-mac Sony -Pn -v --reason -oN results/firewarllevasion/fe_macspoofsonyresult.txt'
  ["fe_macspoofnetgearresult.txt"]='nmap -sT -PO --spoof-mac Netgear -Pn -v --reason -oN results/firewarllevasion/fe_macspoofnetgearresult.txt'
  ["fe_macspooftplinkresult.txt"]='nmap -sT -PO --spoof-mac TP-Link -Pn -v --reason -oN results/firewarllevasion/fe_macspooftplinkresult.txt'
  ["fe_macspoofasusresult.txt"]='nmap -sT -PO --spoof-mac ASUS -Pn -v --reason -oN results/firewarllevasion/fe_macspoofasusresult.txt'
  ["fe_macspoofjuniperresult.txt"]='nmap -sT -PO --spoof-mac Juniper -Pn -v --reason -oN results/firewarllevasion/fe_macspoofjuniperresult.txt'
  ["fe_macspoofbroadcomresult.txt"]='nmap -sT -PO --spoof-mac Broadcom -Pn -v --reason -oN results/firewarllevasion/fe_macspoofbroadcomresult.txt'
  ["fe_macspoofqualcommresult.txt"]='nmap -sT -PO --spoof-mac Qualcomm -Pn -v --reason -oN results/firewarllevasion/fe_macspoofqualcommresult.txt'
  ["fe_badchecksumresult.txt"]='nmap --badsum -v --reason -oN results/firewarllevasion/fe_badchecksumresult.txt'
  ["fe_exoticflagresult.txt"]='nmap -sF -p1-100 -T4 -v --reason -oN results/firewarllevasion/fe_exoticflagresult.txt'
  ["fe_sourceportcheckresult.txt"]='nmap -sS -v -v -Pn -v --reason -oN results/firewarllevasion/fe_sourceportcheckresult.txt'
  ["fe_sourceportresult.txt"]='nmap -g -Pn -v --reason -oN results/firewarllevasion/fe_sourceportresult.txt'
  ["fe_icpmechorequestresult.txt"]='nmap -n -sn -PE -T4 -v --reason -oN results/firewarllevasion/fe_icpmechorequestresult.txt'
  ["fe_packettracceresult.txt"]='nmap -vv -n -sn -PE -T4 --packet-trace -v --reason -oN results/firewarllevasion/fe_packettracceresult.txt'
)

# Create results directory
mkdir -p results
mkdir -p results/firewarllevasion

# Check if only firewall evasion scans are needed
if [[ "$firewall_evasion" = true ]]; then
  for output_file in "${!firewall_evasion_scripts[@]}"; do
    if [[ -n "$targets_file" ]]; then
      ${firewall_evasion_scripts[$output_file]} -iL "$targets_file"
    elif [[ -n "$single_target" ]]; then
      ${firewall_evasion_scripts[$output_file]} "$single_target"
    fi
    scan_complete "results/firewarllevasion/$output_file"
  done
  echo "Firewall evasion scans completed! Output files are in the 'firewarllevasion' directory."
  exit 0
fi

# Define associative array for scripts
declare -A scripts=(
  ["smbsec1.txt"]='nmap -p 139,445 --script smb-security-mode,smb2-security-mode -oN results/smbsec1.txt -v'
  ["smbsec2.txt"]='nmap -p 139,445 -vv -Pn --script=smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010 -oN results/smbsec2.txt -v'
  ["sslcipher.txt"]='nmap --script ssl-enum-ciphers -p 443,1443,389,3389 -oN results/sslcipher.txt -v'
  ["netbiosinfodis.txt"]='nmap -sU -sV -T4 --script nbstat -p137 -Pn -n -oN results/netbiosinfodis.txt -v'
  ["oracletnsversion.txt"]='nmap --script oracle-tns-version -p 1521 -T4 -sV -oN results/oracletnsversion.txt -v'
  ["oraclesidbrute.txt"]='nmap --script oracle-sid-brute -p 1521 -T4 -sV -oN results/oraclesidbrute.txt -v'
  ["ntpservice.txt"]='nmap -sU -sV --script ntp-monlist,ntp-info -p 123 -oN results/ntpservice.txt -v'
  ["snmpinfodis.txt"]='nmap -sV --script snmp-brute -p161 -vvv -oN results/snmpinfodis.txt -v'
  ["ldap.txt"]='nmap -n -sV --script ldap*,ldap-search,ldap-novell-getpass -p 389,636,3268,3269 -oN results/ldap.txt -v'
  ["httpvuln80.txt"]='nmap -p80 --script http-vuln* -oN results/httpvuln80.txt -v'
  ["portmapper111.txt"]='nmap -sSUC -p111 -oN results/portmapper111.txt -v'
  ["mysql.txt"]='nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -oN results/mysql.txt -v'
  ["mssql.txt"]='nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 -oN results/mssql.txt -v'
  ["sshenumalgos.txt"]='nmap -p22 --script ssh2-enum-algos -oN results/sshenumalgos.txt -v'
  ["sshweakkeys.txt"]='nmap -p22 --script ssh-hostkey --script-args ssh_hostkey=full -oN results/sshweakkeys.txt -v'
  ["sshcheckauth.txt"]='nmap -p22 --script ssh-auth-methods --script-args="ssh.user=root" -oN results/sshcheckauth.txt -v'
  ["telnetservice.txt"]='nmap -n -sV -Pn --script telnet-brute,telnet-encryption -p 23 -oN results/telnetservice.txt -v'
  ["dnsvuln.txt"]='nmap -n --script default,dns-fuzz,dns-brute,dns-cache-snoop -p 53 -oN results/dnsvuln.txt -v'
  ["pop3.txt"]='nmap --script pop3-capabilities,pop3-ntlm-info -sV -p 110 -oN results/pop3.txt -v'
  ["nfs.txt"]='nmap --script=nfs-ls,nfs-showmount,nfs-statfs -p 2049 -oN results/nfs.txt -v'
  ["rdpscript.txt"]='nmap --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info -p 3389 -T4 -oN results/rdpscript.txt -v'
  ["apacheajp.txt"]='nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 -oN results/apacheajp.txt -v'
  ["ftp.txt"]='nmap --script ftp-* -p 21 -oN results/ftp.txt -v'
  ["tftp.txt"]='nmap -n -Pn -sU -p69 -sV --script tftp-enum -oN results/tftp.txt -v'
  ["wildcardcert.txt"]='nmap --script ssl-cert -p443 -oN results/wildcardcert.txt -v'
  ["smtp.txt"]='nmap --script smtp-commands,smtp-open-relay,smtp-enum-users -p 25,465,587 -oN results/smtp.txt -v'
  ["tcp.txt"]='nmap -sC -sV -oN results/tcp.txt -v --reason'
  ["udp.txt"]='nmap -sC -sU -oN results/udp.txt -v --reason'
  ["allports.txt"]='nmap -p- -T4 -oN results/allports.txt -v --reason'
)

# Add vulners script if specified
if [[ "$add_vulners" = true ]]; then
  for key in "${!scripts[@]}"; do
    scripts[$key]=${scripts[$key]/--script /--script vulners,}
  done
fi

# Add vuln script if specified
if [[ "$add_vuln" = true ]]; then
  for key in "${!scripts[@]}"; do
    scripts[$key]=${scripts[$key]/--script /--script vuln,}
  done
fi

# Add vuln and vulners script if specified
if [[ "$add_vuln_vulners" = true ]]; then
  for key in "${!scripts[@]}"; do
    scripts[$key]=${scripts[$key]/--script /--script vuln,vulners,}
  done
fi

# Loop through each script and target combination
for output_file in "${!scripts[@]}"; do
  if [[ -n "$targets_file" ]]; then
    ${scripts[$output_file]} -iL "$targets_file"
  elif [[ -n "$single_target" ]]; then
    ${scripts[$output_file]} "$single_target"
  fi
  scan_complete "results/$output_file"
done

# Additional CrackMapExec command for SMBv1 detection
if [[ -n "$targets_file" ]]; then
  crackmapexec smb -p 445 "$targets_file" | grep SMBv1:True > results/smbv1.txt
elif [[ -n "$single_target" ]]; then
  echo "$single_target" > single_target.txt
  crackmapexec smb -p 445 single_target.txt | grep SMBv1:True > results/smbv1.txt
  rm single_target.txt
fi

echo "All scans completed! Output files are in the 'results' directory. Happy hacking!"
