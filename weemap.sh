#!/bin/bash

# Check if targets file is provided
if [ $# -eq 0 ]; then
  echo "Error: Please provide a file containing target IPs as an argument (e.g., ./script.sh targets.txt)"
  exit 1
fi

# Define target file
TARGETS="$1"

# Function to run Nmap scan with specific script and output file
run_nmap_script() {
  local script="$1"
  local outfile="$2"
  nmap $script -iL "$TARGETS" -oN "$outfile"
}

# Run Nmap scans with individual scripts and output files
run_nmap_script "--script smb-security-mode,smb2-security-mode -p 445" "p445smb.txt"
run_nmap_script "--script ssl-enum-ciphers -p 443,1443,389,3389" "sslcipher.txt"
run_nmap_script "-sU -sV -T4 --script nbstat.nse -p 137 -Pn -n" "netbiosinfodis.txt"
run_nmap_script "--script \"oracle-tns-version\" -p 1521 -T4 -sV" "oracletnsversion.txt"  # Corrected script name
run_nmap_script "-sU -sV --script \"ntp* and (discovery or vuln) and not (dos or brute)\" -p 123" "ntpservice.txt"
run_nmap_script "-sV --script \"snmp-brute\" -p 161 -vvv" "snmpinfodis.txt"
run_nmap_script "-n -sV --script \"ldap* and not brute\" " "ldap.txt"
run_nmap_script "-sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122" "mysql.txt"
run_nmap_script "-p 22 --script ssh-hostkey --script-args ssh_hostkey=full" "sshhostkey.txt"

echo "Nmap scans completed. Output files are in the current directory."
