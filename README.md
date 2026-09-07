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

- Bash 3.0 or higher (works with the Bash 3.2 that ships with macOS)
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

## Installing the requirements automatically

lazymap can install whatever is missing for you:

```
sudo ./lazymap.sh --install-deps
```

That checks every required tool, installs the missing ones, and exits. Add it
to a scan command instead (`sudo ./lazymap.sh -t hosts --install-deps`) to
install and then continue straight into the scan.

If you just start a scan on a machine with missing tools, lazymap lists all of
them at once and offers to install them before doing anything else. Answer `y`
to proceed, or pass `-y`/`--yes` to skip the prompt in scripted runs.

Supported package managers: apt, dnf, yum, pacman, zypper, and Homebrew.
Tools with no distro package (NetExec, ssh-audit on non-Debian systems) are
installed with pipx, falling back to `pip3 --user`. Anything that cannot be
installed automatically - Metasploit outside Kali, for example - is reported
with a pointer to its installer rather than failing silently.
  
# Installation

```
git clone https://github.com/evanricafort/lazymap.git && cd lazymap && sudo chmod +x lazymap.sh lib/*.sh extra/*.sh reports/*.sh scans/*.sh && sudo ./lazymap.sh -h
```

# Usage

- Single Host: ./lazymap.sh -u host <options>
- Multiple Hosts/Subnet: ./lazymap.sh -t hosts <options>
- Example Usage: ./lazymap.sh -t hosts -12bank --pret --exclude-udp --interface eth0 -o my_scan

Note: Run in sudo mode to execute NMAP scripts related to UDP scan and Responder.

# Printer Security Check (PRET)

`--pret` sets PRET up automatically before the scan starts - it is cloned into
`pret_tool/` inside the lazymap directory and given its own virtualenv, so the
dependencies do not touch system Python and PEP 668 does not block them. The
setup happens during the dependency phase, so a failure shows up immediately
instead of after the scan has been running for an hour.

```
sudo ./lazymap.sh -t hosts --pret
```

Printers are taken from the nmap PJL scan (port 9100), like every other module
takes its targets from the nmap output, and PRET is driven with a file of
read-only PJL commands so it cannot hang waiting on its interactive prompt. If
no printer is found on 9100, it falls back to PRET's own local discovery.
Output goes to `<output_dir>/pret/`.

If PRET cannot be installed, the printer check is skipped with a warning and the
rest of the scan and the HTML report still complete.

# IPv6 DNS Takeover (mitm6)

Windows prefers IPv6 over IPv4 and has it enabled by default, so a rogue DHCPv6
server can become the network's DNS server and redirect name lookups - including
WPAD - to the tester. lazymap tests this with `mitm6` plus
`impacket-ntlmrelayx`, relaying captured authentication to the domain
controllers found during the LDAP scan.

```
sudo ./lazymap.sh -t hosts --mitm6 --mitm6-interface eth0 --domain CORP.EXAMPLE.COM
```

This test is different from everything else in lazymap: it is an **active
attack**. mitm6 answers DHCPv6 solicits and spoofs DNS for every Windows host in
the broadcast domain, not only the hosts in your target list, and ntlmrelayx
relays the credentials that come back. Because of that:

- It only runs when `--mitm6` is passed, and it needs root.
- It asks you to type the interface name to confirm before starting. `-y` skips
  the prompt for scripted runs; a non-interactive shell without `-y` skips the
  test rather than attacking silently.
- It is time-boxed by `--mitm6-time` (default 300 seconds, minimum 30) so the
  rest of the scan still finishes.
- Relay targets come from the LDAP scan, preferring LDAPS (636) over LDAP (389)
  because relaying to plain LDAP usually fails once signing is enforced.

Output lands in `<output_dir>/mitm6/`: `ntlmrelayx.log`, `mitm6.log`, the
`loot/` directory, and `relayed_accounts.txt` listing every account whose
authentication was successfully relayed. That file is the evidence of the
finding - if it is non-empty, the domain is vulnerable.

Running Responder (`--interface`) at the same time is possible but not advised:
both answer WPAD and they compete for the same requests. lazymap warns when both
are enabled.

# Kerberos Domain Username Enumeration

When a host exposes Kerberos on port 88, lazymap runs
`auxiliary/gather/kerberos_enumusers` against it, the same way it runs the RDP,
RPC, Oracle, AFP, NTP and SNMP modules. Results land in
`<output_dir>/msfkerberos/`, and any accounts the module confirms are written
to a `*_valid_users.txt` file next to the raw output.

The module needs a realm and a username list on top of the target:

- Realm: taken from `--domain`, otherwise recovered from the scan output
  (LDAP rootDSE naming context, then smb-os-discovery / nbstat domain name).
  If neither yields a domain, the scan is skipped with a note rather than
  running against a wrong realm.
- Username list: `--userlist`, otherwise the bundled
  `extra/wordlists/kerberos_users.txt`, otherwise Metasploit's
  `unix_users.txt` if it is installed.

```
./lazymap.sh -u 192.0.2.10 --domain CORP.EXAMPLE.COM
./lazymap.sh -t hosts --domain CORP.EXAMPLE.COM --userlist /usr/share/metasploit-framework/data/wordlists/unix_users.txt
```

`--domain` is also passed to the `krb5-enum-users` NSE script, which otherwise
uses its default `test` realm.

# Scan behaviour notes

Each nmap module writes both normal and greppable output from a single scan.
Earlier versions produced the greppable file with a second `nmap -sV -oG` run
that had no `-p` and no `-v`: a silent version sweep of nmap's top 1000 ports
against every live host, repeated for 13 modules. On a sizeable internal range
that ran for a long time with no output at all and looked like the scan had
frozen. All nmap scans also pass `--stats-every 30s`, so progress is printed
while long scans run.

The NTP Metasploit module (`ntp_peer_list_dos`) can disrupt the time service on
the host it targets, so it is off by default and enabled with `--ntp-dos`.

# Reports

Every run produces `<output_dir>/lazymap_report.html`, including runs that find
nothing. If no live host is found in the target scope, the scan stops early as
before, but the report is still written and records the empty result rather than
leaving you with just a terminal message. The same applies to a firewall evasion
run (`-4`), which previously exited without a report.

When `--discord` is used, the report is sent on from whichever exit path the run
took.

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
