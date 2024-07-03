#!/bin/bash
# Title: lazymap
# Description: A single command line tool equipped with NMAP scripts for Network Penetration Testing that will scan and detect security issues on common ports.
# Author: Evan Ricafort - https://evanricafort.com

# Function to check for script completion
function scan_complete() {
  grep "Nmap scan report for" "$1" &>/dev/null
  if [[ $? -eq 0 ]]; then
    echo "Scan completed for: $(basename "$1") (target: $1)"
  fi
}

# Check if targets file exists
if [[ ! -f "$1" ]]; then
  echo "Error: Targets file '$1' not found!"
  exit 1
fi

# Define associative array for scripts
declare -A scripts=(
  ["smbsec1.txt"]='nmap -p445 --script smb-security-mode,smb2-security-mode -oN smbsec1.txt -v'
  ["smbsec2.txt"]='nmap -p 139,445 -vv -Pn --script=smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-ms17-010 -oN smbsec2.txt -v'
  ["sslcipher.txt"]='nmap --script ssl-enum-ciphers -p 443,1443,389,3389 -oN sslcipher.txt -v'
  ["netbiosinfodis.txt"]='nmap -sU -sV -T4 --script nbstat -p137 -Pn -n -oN netbiosinfodis.txt -v'
  ["oracletnsversion.txt"]='nmap --script oracle-tns-version -p 1521 -T4 -sV -oN oracletnsversion.txt -v'
  ["oraclesidbrute.txt"]='nmap --script oracle-sid-brute -p 1521 -T4 -sV -oN oraclesidbrute.txt -v'
  ["ntpservice.txt"]='nmap -sU -sV --script ntp-monlist,ntp-info -p 123 -oN ntpservice.txt -v'
  ["snmpinfodis.txt"]='nmap -sV --script snmp-brute -p161 -vvv -oN snmpinfodis.txt -v'
  ["ldap.txt"]='nmap -n -sV --script ldap-search,ldap-novell-getpass and not brute --script-args="ldap*" -oN ldap.txt -v'
  ["httpvuln80.txt"]='nmap -p80 --script http-vuln* -oN httpvuln80.txt -v'
  ["portmapper111.txt"]='nmap -sSUC -p111 -oN portmapper111.txt -v'
  ["mysql.txt"]='nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -oN mysql.txt -v'
  ["mssql.txt"]='nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 -oN mssql.txt -v'
  ["sshenumalgos.txt"]='nmap -p22 --script ssh2-enum-algos -oN sshenumalgos.txt -v'
  ["sshweakkeys.txt"]='nmap -p22 --script ssh-hostkey --script-args ssh_hostkey=full -oN sshweakkeys.txt -v'
  ["sshcheckauth.txt"]='nmap -p22 --script ssh-auth-methods --script-args="ssh.user=root" -oN sshcheckauth.txt -v'
  ["telnetservice.txt"]='nmap -n -sV -Pn --script telnet-brute,telnet-encryption -p 23 -oN telnetservice.txt -v'
  ["dnsvuln.txt"]='nmap -n --script default,dns-fuzz,dns-brute,dns-cache-snoop -oN dnsvuln.txt -v'
  ["pop3.txt"]='nmap --script pop3-capabilities,pop3-ntlm-info -sV -p 110 -oN pop3.txt -v'
  ["nfs.txt"]='nmap --script=nfs-ls,nfs-showmount,nfs-statfs -p 2049 -oN nfs.txt -v'
  ["rdpscript.txt"]='nmap --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info -p 3389 -T4 -oN rdpscript.txt -v'
  ["apacheajp.txt"]='nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 -oN apacheajp.txt -v'
)

# Loop through each script and target combination
for output_file in "${!scripts[@]}"; do
  ${scripts[$output_file]} -iL "$1"
  scan_complete "$output_file"
done

echo "All scans completed! Output files are in the current directory. Happy hacking!"
