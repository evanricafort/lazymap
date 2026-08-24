```
 ████                                                                     
░░███                                                                     v0.9
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
- sslscan
- ssh-audit
- screen

Note: CrackMapExec is now distributed as NetExec. lazymap uses `crackmapexec`
when present and otherwise falls back to the `nxc` command, so either one
satisfies the dependency check.
  
# Installation

```
git clone https://github.com/evanricafort/lazymap.git && cd lazymap && sudo chmod +x lazymap.sh lib/*.sh extra/*.sh reports/*.sh scans/*.sh && sudo ./lazymap.sh -h
```

# Usage

- Single Host: ./lazymap.sh -u host <options>
- Multiple Hosts/Subnet: ./lazymap.sh -t hosts <options>
- Example Usage: ./lazymap.sh -t hosts -12bank --pret --exclude-udp --interface eth0 -o my_scan

Note: Run in sudo mode to execute NMAP scripts related to UDP scan and Responder.

# Resume

Long scans can take hours. If a run is interrupted - Ctrl+C, a dropped SSH
session, or a `kill` - lazymap prints how long it ran, how many steps it had
finished, and the exact command to continue:

```
======================================================
⚠  Scan Interrupted (SIGINT) ⚠
======================================================
Run time before interruption : 42 minutes and 18 seconds
Started at                   : Mon Aug 24 09:12:03 2026
Interrupted at               : Mon Aug 24 09:54:21 2026
Completed steps saved        : 21
Partial output directory     : my_scan
------------------------------------------------------
To continue where this run stopped, re-run the same
command with --resume and the same output directory:
  sudo ./lazymap.sh -t hosts -12bank -o my_scan --resume
======================================================
```

Re-running with `--resume` skips everything that already finished:

```
./lazymap.sh -t hosts -12bank -o my_scan --resume
```

How it works:

- Progress is tracked in `<output_dir>/.lazymap_state`, one line per completed step.
- Resume granularity is per step, not per run: each nmap script, each firewall
  evasion scan, each Metasploit module per host, each SSLScan / SSH-Audit /
  LDAP / DNS target, and the PRET check are tracked individually.
- Live host discovery is reused from the interrupted run, so the target list
  stays identical across the resume.
- Without `--resume`, a run reuses the output directory but starts clean - old
  state is discarded so nothing is skipped unintentionally.
- Every run, interrupted or not, ends with a summary showing start time, finish
  time, total run time, and how many steps were skipped.
