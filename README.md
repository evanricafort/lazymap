<img width="1440" alt="Screenshot 2024-09-27 at 3 21 12 PM" src="https://github.com/user-attachments/assets/ad01a031-adcb-4e3f-99cf-abf7cf52784b">

# lazymap

Lazymap is a single command-line tool made for network penetration testing. It is composed of multiple selected NMAP scripts, sslscan, ssh-audit, selected metasploit modules, and an HTTP header security checker.

# Additional Information

* Added _crackmapexec_ to scan and detect **SMBv1** since most of the time when doing internal netpen, there are targets that are running SMB version 1.
* Added _Firewall Evasion_ option to execute **firewall evasion scan** on the targets.
* Added changes that will scan the _-A scripts_ list in a specific order instead of a random loop to avoid hang time.
* Added changes that will exclude all port and udp scans using the _-ap_ command.
* Added sslscan for additional POC for ssl-related issues.
* Added ssh-audit for additional POC for ssh-related issues.
* Added 2 Metasploit modules to scan RDP and RPC issues.
* Merged my 2nd personal project, **CheckThatHeaders**, which scans and detects missing HTTP security header issues.
* Added a feature to determine if the target is within the subnet or individual IP to relay the result without issue for sslscan, ssh-audit and checkthatheaders.
* Added a not so fancy ascii art for the banner.
* Improved verbose and scan outputs.

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

- Usage: ./lazymap.sh -u target _[Single Host]_ or ./lazymap.sh -t multipletarget.txt _[Multiple Hosts]_
- Additional Options: Insert additional scripts with option **-1** for _[vulners]_, **-2** for _[vuln]_, **-3** for both _[vulners & vuln]_ NSE scripts, **-4** for Firewall Evasion Scan and **-ap** if you want to exclude all port scan.
- Reminder: Option **-3** may take some time to finish if you have multiple targets.
- Note: Run in sudo mode to execute NMAP scripts related to UDP scan.
