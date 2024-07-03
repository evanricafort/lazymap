# lazymap

A lazy single command tool equipped with NMAP scripts for Network Penetration Testing that will scan and detect security issues on common ports.

List of Ports
- Port 139 and 445 (SMB)
- Port 443, 1443, 389, 3389 (SSL Cipher)
- Port 137 (NetBIOS)
- Port 1521 (Oracle TNS)
- Port 123 (NTP)
- Port 161 (SNMP)
- Port 389, 636, 3268, 3269 (LDAP)
- Port 80 (HTTP)
- Port 111 (Portmapper)
- Port 3306 (MySQL)
- Port 22 (SSH Hostkey)
- Port 23 (Telnet)
- Port 8009 (Apache AJP)
- Port 3389 (RDP)
- Port 2049 (NFS)
- Port 110 (Pop3)
- Port 53 (DNS)
  

# Installation

- git clone https://github.com/evanricafort/lazymap.git
- cd lazymap
- chmod +x lazymap.sh

# Usage
./lazymap.sh [HOSTS] _hosts file_
