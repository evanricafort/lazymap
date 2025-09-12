```
 ████                                                                     
░░███                                                                     v0.8
 ░███   ██████    █████████ █████ ████ █████████████    ██████   ████████ 
 ░███  ░░░░░███  ░█░░░░███ ░░███ ░███ ░░███░░███░░███  ░░░░░███ ░░███░░███
 ░███   ███████  ░   ███░   ░███ ░███  ░███ ░███ ░███   ███████  ░███ ░███
 ░███  ███░░███    ███░   █ ░███ ░███  ░███ ░███ ░███  ███░░███  ░███ ░███
 █████░░████████  █████████ ░░███████  █████░███ █████░░████████ ░███████ 
░░░░░  ░░░░░░░░  ░░░░░░░░░   ░░░░░███ ░░░░░ ░░░ ░░░░░  ░░░░░░░░  ░███░░░  
                             ███ ░███                            ░███     
                            ░░██████                             █████    
                             ░░░░░░                             ░░░░░
                       [network penetration testing kit]
```

# lazymap

lazymap is a single command-line tool for network penetration testing. it combines multiple selected nmap scripts, sslscan, ssh-audit, dig, ldapsearch, curl, rpcclient, selected metasploit modules, PRET and wget. 

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
- screen
  
# Installation

```
git clone https://github.com/evanricafort/lazymap.git && cd lazymap && sudo chmod +x lazymap.sh lib/*.sh extra/*.sh reports/*.sh scans/*.sh && sudo ./lazymap.sh -h
```

# Usage

- Single Host: ./lazymap.sh -u host <options>
- Multiple Hosts/Subnet: ./lazymap.sh -t hosts <options>
- Example Usage: ./lazymap.sh -t hosts -12bank --pret --exclude-udp --interface eth0 -o my_scan
