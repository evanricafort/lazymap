#!/bin/bash
# Title: lazymap
# Description: Lazymap is a single command-line tool made for network penetration testing.
# It combines multiple selected NMAP scripts, sslscan, ssh-audit, dig, ldapsearch, curl, rpcclient, selected metasploit modules, PRET and wget.
# Author: Evan Ricafort - https://evanricafort.com | X: @evanricafort

# Source all necessary libraries and configuration files
source "lib/colors.sh"
source "lib/display.sh"
source "lib/checks.sh"
source "lib/nmap_scans.sh"
source "lib/other_scans.sh"
source "lib/metasploit_scans.sh"
source "lib/pret_scan.sh"
source "lib/firewall_evasion.sh"
source "lib/report_generator.sh"

# Check for Bash version 4 or higher
if ((BASH_VERSINFO[0] < 4)); then
    echo -e "${RED}Error: This script requires Bash version 4 or higher.${NC}"
    exit 1
fi

# Display ASCII art on every run
display_ascii_art

# Global Variables
declare -A NMAP_SCRIPTS
declare -A FIREWALL_EVASION_SCRIPTS
declare -a ordered_scripts
declare -a ordered_firewall_evasion_scripts

# Variables to check if options are set
a_option_set=false
add_vulners=false
add_vuln=false
exclude_sslscan=false
exclude_sshaudit=false
exclude_checkheaders=false
add_A_minrate_open=false
add_nT4=false
pret_option=false
firewall_evasion=false
targets_file=""
single_target=""

# --- Function Calls from sourced scripts ---
initialize_nmap_scripts
initialize_firewall_evasion_scripts

# --- Option Parsing ---
OPTS=$(getopt -o t:u:1234ankhb --long pret -n "$0" -- "$@")
if [ $? != 0 ]; then
    echo -e "${RED}Error parsing options${NC}"
    exit 1
fi
eval set -- "$OPTS"

while true; do
    case "$1" in
        -t ) targets_file=$2; shift 2 ;;
        -u )
            OPTARG=$2
            if [[ "$OPTARG" == *","* || "$OPTARG" == *" "* || "$OPTARG" == *"/"* ]]; then
                echo -e "${RED}Error: -u option accepts only a single IP address or hostname without spaces, commas, or subnets.${NC}"
                exit 1
            fi
            single_target="$OPTARG"
            shift 2
            ;;
        -1 ) add_vulners=true; shift ;;
        -2 ) add_vuln=true; shift ;;
        -3 ) add_vuln=true; add_vulners=true; shift ;;
        -4 ) firewall_evasion=true; shift ;;
        -a ) a_option_set=true; shift ;;
        -n ) add_nT4=true; shift ;;
        -k ) exclude_sslscan=true; exclude_sshaudit=true; exclude_checkheaders=true; shift ;;
        -b ) add_A_minrate_open=true; shift ;;
        -h ) display_help; shift ;;
        --pret ) pret_option=true; shift ;;
        -- ) shift; break ;;
        * ) break ;;
    esac
done

# Input validation and checks
if [[ -n "$targets_file" && -n "$single_target" ]]; then
    echo -e "${RED}Error: Cannot specify both a targets file (-t) and a single target (-u).${NC}"
    exit 1
fi

if [[ -n "$targets_file" && ! -f "$targets_file" ]]; then
    echo -e "${RED}Error: Targets file '$targets_file' not found!${NC}"
    exit 1
elif [[ -z "$targets_file" && -z "$single_target" ]]; then
    echo -e "${GREEN}Use the -h option for help.${NC}"
    exit 1
fi

# Check for required tools
check_all_commands

# Execute scans
if [[ "$firewall_evasion" = true ]]; then
    run_firewall_evasion_scans "$targets_file" "$single_target"
    exit 0
fi

# Apply optional arguments to Nmap commands
apply_nmap_options

# Run the main Nmap scans
run_nmap_scans "$targets_file" "$single_target"

# Run the other scans (SSLScan, SSH-Audit, etc.)
run_other_scans "$targets_file" "$single_target"

# Run the Metasploit scans
run_metasploit_scans

# Run PRET scan
if [[ "$pret_option" = true ]]; then
    run_pret_scan
fi
