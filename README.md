
<img width="574" height="154" alt="ascii-text-art" src="https://github.com/user-attachments/assets/eb31cbdf-191b-41c9-94e1-2b7bdd6045c3" />

# lazymap

Lazymap is a single command-line tool made for network penetration testing. It combines multiple selected NMAP scripts, sslscan, ssh-audit, dig, ldapsearch, curl, rpcclient, selected metasploit modules, and wget.

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
  
# Installation

```
git clone https://github.com/evanricafort/lazymap.git && cd lazymap && sudo chmod +x lazymap.sh lib/*.sh && sudo ./lazymap.sh -h
```

# Usage

- Usage: ./lazymap.sh -u host _[Single Host]_ or ./lazymap.sh -t hosts.txt _[Multiple Hosts]_
- Additional Options: Insert additional scripts with option **-1** for _[vulners]_, **-2** for _[vuln]_, **-3** for both _[vulners & vuln]_ NSE scripts, **-4** for Firewall Evasion Scan, **-a** exclude the all ports scan and UDP scan, **-N** to add -n -T4 to Nmap command for faster scanning and **-k** to exclude sslscan, ssh-audit, and CheckThatHeaders scans.
- Reminder: Option **-3** may take some time to finish if you have multiple targets.
- Note: Run in sudo mode to execute NMAP scripts related to UDP scan.
