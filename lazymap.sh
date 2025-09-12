#!/usr/bin/env bash

# lazymap.sh
# Main.

# Global variables
start_time=$(date +%s)
start_date=$(date)
output_dir="results"
declare -a TARGETS
declare -A OPTIONS

# Include libraries and scripts
source "lib/colors.sh"
source "lib/help.sh"
source "lib/checks.sh"
source "scans/nmap.sh"
source "scans/web.sh"
source "scans/metasploit.sh"
source "scans/smb.sh"
source "scans/ldap.sh"
source "scans/dns.sh"
source "scans/pret.sh"
source "extra/responder.sh"
source "reports/html_report.sh"
source "scans/live_hosts.sh"

main() {
    # Display ASCII art on every run
    display_ascii_art

    # --- Option Parsing ---
    TEMP=$(getopt -o t:u:1234ankhbo: --long pret,interface:,help,exclude-udp -n "$0" -- "$@")
    if [ $? != 0 ]; then
        echo -e "${RED}Error: Failed to parse options.${NC}" >&2
        exit 1
    fi
    eval set -- "$TEMP"

    while true; do
        case "$1" in
            -t ) targets_file=$2; shift 2 ;;
            -u )
                if [[ "$2" == *","* || "$2" == *" "* || "$2" == *"/"* ]]; then
                    echo -e "${RED}Error: -u option accepts only a single IP address or hostname.${NC}"
                    exit 1
                fi
                single_target=$2; shift 2 ;;
            -1 ) OPTIONS[vulners]=true; shift ;;
            -2 ) OPTIONS[vuln]=true; shift ;;
            -3 ) OPTIONS[vulners]=true; OPTIONS[vuln]=true; shift ;;
            -4 ) OPTIONS[firewall_evasion]=true; shift ;;
            -a ) OPTIONS[exclude_allports]=true; shift ;;
            -n ) OPTIONS[add_nT4]=true; shift ;;
            -k ) OPTIONS[exclude_web_scans]=true; shift ;;
            -b ) OPTIONS[add_A_minrate_open]=true; shift ;;
            -o ) output_dir=$2; shift 2 ;;
            --pret ) OPTIONS[pret]=true; shift ;;
            --interface ) OPTIONS[responder_interface]=$2; shift 2 ;;
            --exclude-udp ) OPTIONS[exclude_udp]=true; shift ;;
            -h | --help ) display_help; exit 0 ;;
            -- ) shift; break ;;
            * ) break ;;
        esac
    done

    # Run Responder immediately if the option is specified
    if [[ -n "${OPTIONS[responder_interface]}" ]]; then
        run_responder "${OPTIONS[responder_interface]}" "$output_dir" & # Run in the background
    fi

    if [[ -n "$targets_file" && -n "$single_target" ]]; then
        echo -e "${RED}Error: Cannot specify both a targets file (-t) and a single target (-u).${NC}"
        exit 1
    fi

    if [[ -n "$targets_file" ]]; then
        if [[ ! -f "$targets_file" ]]; then
            echo -e "${RED}Error: Targets file '$targets_file' not found!${NC}"
            exit 1
        fi
        readarray -t TARGETS < "$targets_file"
    elif [[ -n "$single_target" ]]; then
        TARGETS+=("$single_target")
    else
        echo -e "${RED}Error: No targets specified. Use -h for help.${NC}"
        exit 1
    fi

    # Check for required dependencies
    check_dependencies

    # Setup directories
    mkdir -p "$output_dir"
    mkdir -p "$output_dir/nmap"

    # Run live host check as a separate module, but only for subnets or multiple targets
    if [[ "${#TARGETS[@]}" -gt 1 ]] || [[ "${TARGETS[0]}" == *"/"* ]]; then
      run_live_host_scans
    else
      # For a single IP, create the live_hosts.txt file directly
      printf "%s\n" "${TARGETS[@]}" > "$output_dir/live_hosts.txt"
    fi

    # --- Main Scan Workflow ---
    if [[ "${OPTIONS[firewall_evasion]}" == true ]]; then
        echo -e "${YELLOW}Starting Firewall Evasion Scans.${NC}\n"
        run_firewall_evasion_scans "$output_dir"
        echo -e "${BLUE}Firewall evasion scans completed.${NC}"
        exit 0
    fi

    echo -e "${YELLOW}Starting Network Penetration Scans.${NC}\n"

    # Run Nmap Scans
    run_nmap_scans "$output_dir"

    # Run Web Scans
    if [[ "${OPTIONS[exclude_web_scans]}" != true ]]; then
        run_web_scans "$output_dir" "${TARGETS[@]}"
    fi

    # Run Metasploit Scans
    run_metasploit_scans "$output_dir"

    # Run SMB Scans
    run_smb_scans "$output_dir" "${TARGETS[@]}"

    # Run LDAP Scan
    run_ldap_scan "$output_dir" "${TARGETS[@]}"

    # Run DNS Scan
    run_dns_scan "$output_dir"

    # Run PRET Scan
    if [[ "${OPTIONS[pret]}" == true ]]; then
        run_pret_scan "$output_dir"
    fi

    # Generate HTML Report
    end_time=$(date +%s)
    end_date=$(date)
    generate_html_report "$output_dir" "$start_date" "$end_date"

    echo -e "${GREEN}All scans completed. Check the '$output_dir' directory for outputs.${NC}\n"
    echo -e "${GREEN}Happy Hacking! - evan (@evanricafort)${NC}"
}
main "$@"
