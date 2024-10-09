<img width="1440" alt="Screenshot 2024-10-09 at 7 22 18 PM" src="https://github.com/user-attachments/assets/19fef66b-163e-4132-9f65-3c62a472c842">


# lazymap

Lazymap is a single command-line tool made for network penetration testing. It combines multiple selected NMAP scripts, sslscan, ssh-audit, dig, ldapsearch, curl, rpcclient, selected metasploit modules, and wget.

# Additional Information
# v0.5

* Added sslscan for additional POC for ssl-related issues.
* Added ssh-audit for additional POC for ssh-related issues.
* Added 2 Metasploit modules to scan RDP and RPC issues.
* Merged my 2nd personal project, **CheckThatHeaders**, which scans and detects missing HTTP security header issues.
* Added a feature to determine if the target is within the subnet or individual IP to relay the result without issue for sslscan, ssh-audit and checkthatheaders.
* Added a not so fancy ascii art for the banner.
* Improved verbose and scan outputs.

# v0.6

* Added another metasploit module for Oracle TNS SID Enumeration.
* Added 'dig' for DNSSec vulnerability scan.
* Added 'ldapsearch' for LDAP Anonymous Bind scan.
* Added 'rpcclient' for Unauthenticated RPC scan.
* Added 'curl' for Default IIS Webpage detection.
* Re-configured 'checkthatheaders' to scan live host (Port 80, 443, 8443, 8080) only.
* Added -k flag to exclude sslscan, ssh-audit, and CheckThatHeaders scans.
* Added -a flag to exclude the all ports scan and UDP scan.
* Added -N flag to add -n -T4 to Nmap command for faster scanning.
* Added -h flag to display this help message.
* Added a feature to combine multiple flags.
* Improved verbose and scan outputs.

# Requirements

- Bash version 4 or higher
- nmap
- curl
- dig
- ldapsearch
- rpcclient
- metasploit
- wget
- sslscan
- ssh-audit

# List of Ports
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
- Port 22 (SSH)
- Port 23 (Telnet)
- Port 8009 (Apache AJP)
- Port 3389 (RDP)
- Port 2049 (NFS)
- Port 110 (Pop3)
- Port 53 (DNS)
- Port 21 (FTP)
- Port 69 (TFTP)
- Port 25,465,587 (SMTP)
- Port 623 (IPMI)
- Port 143 and 993 (IMAP)
- Port 500 (IKE)
- Port 548 (AFP)
- Port 70 (Gopher)
- Port 88 (Kerberos)
- Port 6379 (Redis)
- Port 5900 (VNC)
- Port 5060 (SIP)
  
# Installation

```
git clone https://github.com/evanricafort/lazymap.git && cd lazymap && sudo chmod +x lazymap.sh && sudo ./lazymap.sh -h
```

# Usage

- Usage: ./lazymap.sh -u host _[Single Host]_ or ./lazymap.sh -t hosts.txt _[Multiple Hosts]_
- Additional Options: Insert additional scripts with option **-1** for _[vulners]_, **-2** for _[vuln]_, **-3** for both _[vulners & vuln]_ NSE scripts, **-4** for Firewall Evasion Scan, **-a** exclude the all ports scan and UDP scan, **-N** to add -n -T4 to Nmap command for faster scanning and **-k** to exclude sslscan, ssh-audit, and CheckThatHeaders scans.
- Reminder: Option **-3** may take some time to finish if you have multiple targets.
- Note: Run in sudo mode to execute NMAP scripts related to UDP scan.
