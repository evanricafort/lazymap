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
source "lib/smbv1_cme.sh"
source "lib/dns_vulns.sh"
source "lib/ldap_anon_bind.sh"
source "lib/rpc_unauth.sh"
source "lib/iis_detection.sh"
source "lib/metasploit_scans.sh"
source "lib/pret_scan.sh"
source "lib/firewall_evasion.sh"
source "lib/report_generator.sh"
source "lib/responder_handler.sh"

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
add_nT4=true
pret_option=false
firewall_evasion=false
targets_file=""
single_target=""

# --- Function Calls from sourced scripts ---
initialize_nmap_scripts
initialize_firewall_evasion_scripts

# --- Option Parsing ---
OPTS=$(getopt -o t:u:124ankhRb --long pret,discord:,responder: -n "$0" -- "$@")
if [ $? != 0 ]; then
    echo -e "${RED}Error parsing options${NC}"
    exit 1
fi
eval set -- "$OPTS"

while true; do
    case "$1" in
        -t ) targets_file=$2; echo -e "${GREEN}Targets file specified: ${targets_file}${NC}"; shift 2 ;;
        -u )
            OPTARG=$2
            if [[ "$OPTARG" == *","* || "$OPTARG" == *" "* || "$OPTARG" == *"/"* ]]; then
                echo -e "${RED}Error: -u option accepts only a single IP address or hostname without spaces, commas, or subnets.${NC}"
                exit 1
            fi
            single_target="$OPTARG"
            echo -e "${GREEN}Single target specified: ${single_target}${NC}"
            shift 2
            ;;
        -1 ) add_vulners=true; echo -e "${GREEN}Option -1 included: Adding vulners scripts.${NC}"; shift ;;
        -2 ) add_vuln=true; echo -e "${GREEN}Option -2 included: Adding vulnerability scripts.${NC}"; shift ;;
        -4 ) firewall_evasion=true; echo -e "${GREEN}Option -4 included: Performing firewall evasion scans.${NC}"; shift ;;
        -a ) a_option_set=true; echo -e "${GREEN}Option -a included: Performing intense scans on open ports only.${NC}"; shift ;;
        -n ) add_nT4=true; echo -e "${GREEN}Option -n included: Setting Nmap timing template to T4.${NC}"; shift ;;
        -k ) exclude_sslscan=true; exclude_sshaudit=true; exclude_checkheaders=true; echo -e "${GREEN}Option -k included: Excluding sslscan, ssh-audit, and checkheaders.${NC}"; shift ;;
        -b ) add_A_minrate_open=true; echo -e "${GREEN}Option -b included: Adding -A --min-rate 2000 to Nmap scans.${NC}"; shift ;;
        -h ) display_help; exit 0 ;;
        --pret ) pret_option=true; echo -e "${GREEN}Option --pret included: Performing PRET scan.${NC}"; shift ;;
        --responder ) shift; responder_option=true; responder_interface=$1; echo -e "${GREEN}Option --responder included: Starting Responder on interface ${responder_interface}.${NC}"; shift ;;
        -- ) shift; break ;;
        * ) break ;;
    esac
done

# --- Main Logic ---

# Check for required tools
check_all_commands

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

# Function to add vulnerability scripts based on options -1 and -2
add_vuln_scripts() {
    if [[ "$add_vuln" = true ]]; then
        echo -e "${YELLOW}Adding Nmap vuln scripts to all scans.${NC}"
        for script_name in "${!NMAP_SCRIPTS[@]}"; do
            NMAP_SCRIPTS[$script_name]+=" --script vuln"
        done
    fi

    if [[ "$add_vulners" = true ]]; then
        echo -e "${YELLOW}Adding Nmap vulners scripts to all scans.${NC}"
        for script_name in "${!NMAP_SCRIPTS[@]}"; do
            NMAP_SCRIPTS[$script_name]+=" --script vulners"
        done
    fi
}

# Apply optional arguments to Nmap commands
apply_nmap_options() {
    if [[ "$a_option_set" = true ]]; then
        echo -e "${YELLOW}The -a option is set, excluding the full port scan and UDP scan.${NC}"
        NMAP_SCRIPTS["tcp"]="nmap -sV -sT -oN results/tcp.nmap"
        unset 'NMAP_SCRIPTS["udp"]'
    fi

    if [[ "$add_nT4" = true ]]; then
        echo -e "${YELLOW}The -n option is set, adding timing to all nmap scans.${NC}"
        for script_name in "${!NMAP_SCRIPTS[@]}"; do
            NMAP_SCRIPTS[$script_name]+=" -n -T4"
        done
    fi

    if [[ "$add_A_minrate_open" = true ]]; then
        echo -e "${YELLOW}The -b option is set, adding aggressive flags to all nmap scans.${NC}"
        for script_name in "${!NMAP_SCRIPTS[@]}"; do
            NMAP_SCRIPTS[$script_name]+=" -A --min-rate 1000 --open"
        done
    fi
    
    # Call the new function to handle vulnerability scripts
    add_vuln_scripts
}
apply_nmap_options

run_other_scans() {
    local targets_file="$1"
    local single_target="$2"
    
    echo -e "${GREEN}Starting other scans...${NC}"

    if [[ "$exclude_sslscan" != true ]]; then
        if command -v sslscan &> /dev/null; then
            echo -e "${CYAN}Running sslscan...${NC}"
            if [[ -n "$targets_file" ]]; then
                while read -r target; do
                    sslscan "$target" >> "results/sslscan.txt" 2>&1
                done < "$targets_file"
            elif [[ -n "$single_target" ]]; then
                sslscan "$single_target" >> "results/sslscan.txt" 2>&1
            fi
        else
            echo -e "${YELLOW}sslscan not found. Skipping...${NC}"
        fi
    else
        echo -e "${YELLOW}Skipping sslscan as requested.${NC}"
    fi

    if [[ "$exclude_sshaudit" != true ]]; then
        if command -v ssh-audit &> /dev/null; then
            echo -e "${CYAN}Running ssh-audit...${NC}"
            if [[ -n "$targets_file" ]]; then
                ssh-audit -T "$targets_file" >> "results/sshaudit.txt" 2>&1
            elif [[ -n "$single_target" ]]; then
                ssh-audit "$single_target" >> "results/sshaudit.txt" 2>&1
            fi
        else
            echo -e "${YELLOW}ssh-audit not found. Skipping...${NC}"
        fi
    else
        echo -e "${YELLOW}Skipping ssh-audit as requested.${NC}"
    fi

    if [[ "$exclude_checkheaders" != true ]]; then
        if command -v curl &> /dev/null; then
            echo -e "${CYAN}Running checkthatheader...${NC}"
            if [[ -n "$targets_file" ]]; then
                while read -r target; do
                    echo "Checking headers for $target..." >> "results/checkthatheader.txt"
                    curl -I "$target" >> "results/checkthatheader.txt" 2>&1
                done < "$targets_file"
            elif [[ -n "$single_target" ]]; then
                echo "Checking headers for $single_target..." >> "results/checkthatheader.txt"
                curl -I "$single_target" >> "results/checkthatheader.txt" 2>&1
            fi
        else
            echo -e "${YELLOW}curl not found. Skipping checkthatheader...${NC}"
        fi
    else
        echo -e "${YELLOW}Skipping checkheaders as requested.${NC}"
    fi
}


# Function to run all scans
run_all_scans() {
    # Run the main Nmap scans
    run_nmap_scans "$targets_file" "$single_target"

    # Run the other scans (SSLScan, SSH-Audit, etc.)
    run_other_scans "$targets_file" "$single_target"

    # Run the Metasploit scans
    run_metasploit_scans

    # Run the IIS Detection scans
    run_iis_detection

    # Run the RPC Unauthenticated scans
    run_rpc_unauth_scan

    # Run the LDAP Anonymous login scans
    run_ldap_anon_bind

    # Run the DNS Vulnerability scans
    run_dns_vulns_scan

    # Run the SMBv1 Service detection scans
    run_cme_smbv1

    # Run PRET scan
    if [[ "$pret_option" = true ]]; then
        run_pret_scan
    fi
}

# Determine the final target information for the report
if [[ -n "$targets_file" ]]; then
    target_info=$(cat "$targets_file" | tr '\n' ' ')
elif [[ -n "$single_target" ]]; then
    target_info="$single_target"
else
    target_info="N/A"
fi

# Conditional execution based on options
if [[ "$responder_option" = true ]]; then
    if [[ -z "$responder_interface" ]]; then
        echo -e "${RED}Please specify a network interface for Responder (e.g., --responder eth0).${NC}"
        exit 1
    fi
    source "lib/responder_handler.sh"
    run_responder "$responder_interface"
elif [[ "$firewall_evasion" = true ]]; then
    run_firewall_evasion_scans "$targets_file" "$single_target"
else
    run_all_scans
fi

# Generate the final HTML report
generate_html_report "$target_info"

exit 0
