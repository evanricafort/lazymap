# lazymap

A single command-line tool to execute multiple NMAP script for network penetration testing that will scan and detect security issues on common ports.

# Additional Information

* Added _crackmapexec_ to scan and detect **SMBv1** since most of the time when doing internal netpen, there are targets that are running SMB version 1.
* Added _Firewall Evasion_ option to execute **firewall evasion scan** on the targets.
* Added changes which will scan the _-A scripts_ list in specific order instead of random loop to avoid hang time.
* Added changes which will exclude all port scan using _-ap_ command.

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
  
# Installation

```
git clone https://github.com/evanricafort/lazymap.git && cd lazymap && sudo chmod +x lazymap.sh && sudo ./lazymap.sh
```

# Usage

- Usage: ./lazymap.sh -u target _[Single Host]_ or ./lazymap.sh -t multipletarget.txt _[Multiple Hosts]_
- Additional Options: Insert additional scripts with option **-1** for _[vulners]_, **-2** for _[vuln]_, **-3** for both _[vulners & vuln]_ NSE scripts, **-4** for Firewall Evasion Scan and **-ap** if you want to exclude all port scan.
- Reminder: Option **-3** may take some time to finish if you have multiple targets.
