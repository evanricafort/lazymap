#!/usr/bin/env bash

# lazymap runs on Bash 3.0 and newer, including the 3.2 shipped by macOS.
if [ -z "${BASH_VERSINFO[0]}" ] || [ "${BASH_VERSINFO[0]}" -lt 3 ]; then
    echo "Error: lazymap requires Bash 3.0 or newer (found ${BASH_VERSION:-unknown})." >&2
    exit 1
fi

# Resolve the installation directory so lazymap can be launched from anywhere.
LAZYMAP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export LAZYMAP_DIR

start_time=$(date +%s)
start_date=$(date)
output_dir="results"
TARGETS=()
discord_webhook=""
RESUME_HINT="sudo ./lazymap.sh --resume"

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"
source "$LAZYMAP_DIR/lib/state.sh"
source "$LAZYMAP_DIR/lib/installer.sh"
source "$LAZYMAP_DIR/lib/help.sh"
source "$LAZYMAP_DIR/lib/checks.sh"
source "$LAZYMAP_DIR/scans/nmap.sh"
source "$LAZYMAP_DIR/scans/web.sh"
source "$LAZYMAP_DIR/scans/metasploit.sh"
source "$LAZYMAP_DIR/scans/smbv1.sh"
source "$LAZYMAP_DIR/scans/unauthrpc.sh"
source "$LAZYMAP_DIR/scans/ldap.sh"
source "$LAZYMAP_DIR/scans/dns.sh"
source "$LAZYMAP_DIR/scans/mitm6.sh"
source "$LAZYMAP_DIR/scans/pret.sh"
source "$LAZYMAP_DIR/extra/responder.sh"
source "$LAZYMAP_DIR/reports/html_report.sh"
source "$LAZYMAP_DIR/reports/send_discord_webhook.sh"
source "$LAZYMAP_DIR/scans/live_hosts.sh"

handle_discord_webhook() {
    if opt_true send_to_discord; then
        echo -e "${YELLOW}Please enter the Discord webhook URL:${NC}"
        read -r discord_webhook
        if [[ -z "$discord_webhook" ]]; then
            echo -e "${RED}Error: No Discord webhook URL provided. Aborting Discord report send.${NC}"
            opt_unset send_to_discord
        fi
    fi
}

# Produces the HTML report and sends it on if --discord was used. Called from
# every exit path so a run always leaves a report behind.
finalise_reports() {
    end_date=$(date)
    generate_html_report "$output_dir" "$start_date" "$end_date"

    if opt_true send_to_discord && [ -n "$discord_webhook" ]; then
        send_discord_webhook "$output_dir" "$discord_webhook" "$start_date"
    fi
}

check_for_live_hosts_and_exit() {
    local live_hosts_file="$output_dir/live_hosts.txt"
    if [[ ! -s "$live_hosts_file" ]]; then
        echo -e "\n${BLUE}======================================================${NC}"
        echo -e "${YELLOW}🚨 Scan Termination Notice 🚨${NC}"
        echo -e "${BLUE}======================================================${NC}"
        echo -e "${CYAN}No live host IP/s were found in the defined target scope.${NC}"
        echo -e "${CYAN}Scanning process has been successfully terminated.${NC}"
        echo -e "${CYAN}Output directory: ${output_dir} (created)${NC}"
        echo -e "${BLUE}======================================================${NC}\n"

        # A report is still produced, recording that the scope had no live hosts.
        finalise_reports

        echo -e "${GREEN}Scan finished in $(elapsed_runtime).${NC}\n"
        exit 0
    fi
}

print_completion_summary() {
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${GREEN}Scan Complete${NC}"
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${CYAN}Started  : ${start_date}${NC}"
    echo -e "${CYAN}Finished : $(date)${NC}"
    echo -e "${CYAN}Run time : $(elapsed_runtime)${NC}"
    if [[ "$RESUME_MODE" == true ]]; then
        echo -e "${CYAN}Resumed  : yes (${SKIPPED_STEPS} step(s) skipped)${NC}"
    fi
    echo -e "${CYAN}Output   : ${output_dir}${NC}"
    echo -e "${BLUE}======================================================${NC}"
}

main() {
    display_ascii_art

    # GNU getopt is required for the long options below.
    getopt --test >/dev/null 2>&1
    if [[ $? -ne 4 ]]; then
        echo -e "${RED}Error: GNU getopt is required (install 'util-linux', or on macOS 'brew install gnu-getopt').${NC}" >&2
        exit 1
    fi

    build_resume_hint "$@"

    TEMP=$(getopt -o t:u:1234ankhbo:y --long pret,interface:,help,exclude-udp,discord,resume,install-deps,yes,domain:,userlist:,mitm6,mitm6-interface:,mitm6-time:,ntp-dos,script-timeout:,host-timeout: -n "$0" -- "$@")
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
            -1 ) opt_set vulners true; shift ;;
            -2 ) opt_set vuln true; shift ;;
            -3 ) opt_set vulners true; opt_set vuln true; shift ;;
            -4 ) opt_set firewall_evasion true; shift ;;
            -a ) opt_set exclude_allports true; shift ;;
            -n ) opt_set add_nT4 true; shift ;;
            -k ) opt_set exclude_web_scans true; shift ;;
            -b ) opt_set add_A_minrate_open true; shift ;;
            -o ) output_dir=$2; shift 2 ;;
            --pret ) opt_set pret true; shift ;;
            --interface ) opt_set responder_interface "$2"; shift 2 ;;
            --exclude-udp ) opt_set exclude_udp true; shift ;;
            --discord ) opt_set send_to_discord true; shift ;;
            --resume ) RESUME_MODE=true; shift ;;
            --domain ) opt_set kerberos_domain "$2"; shift 2 ;;
            --ntp-dos ) opt_set ntp_dos true; shift ;;
            --script-timeout ) opt_set script_timeout "$2"; shift 2 ;;
            --host-timeout ) opt_set host_timeout "$2"; shift 2 ;;
            --mitm6 ) opt_set mitm6 true; shift ;;
            --mitm6-interface ) opt_set mitm6_interface "$2"; shift 2 ;;
            --mitm6-time ) opt_set mitm6_duration "$2"; shift 2 ;;
            --userlist ) opt_set kerberos_userlist "$2"; shift 2 ;;
            --install-deps ) AUTO_INSTALL=true; shift ;;
            -y | --yes ) ASSUME_YES=true; shift ;;
            -h | --help ) display_help; exit 0 ;;
            -- ) shift; break ;;
            * ) break ;;
        esac
    done

    local mitm6_time
    mitm6_time="$(opt_get mitm6_duration)"
    if [ -n "$mitm6_time" ]; then
        case "$mitm6_time" in
            ''|*[!0-9]*) echo -e "${RED}Error: --mitm6-time expects a whole number of seconds.${NC}"; exit 1 ;;
        esac
        if [ "$mitm6_time" -lt 30 ]; then
            echo -e "${RED}Error: --mitm6-time must be at least 30 seconds to observe anything useful.${NC}"
            exit 1
        fi
    fi

    # Allow "--install-deps" on its own to set the machine up with no scan.
    if [[ "$AUTO_INSTALL" == true && -z "$targets_file" && -z "$single_target" ]]; then
        run_install_deps_only
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
        read_lines_into TARGETS < "$targets_file"
        # Drop blank lines and comments so they never reach nmap.
        local cleaned=()
        for t in "${TARGETS[@]}"; do
            t="${t//$'\r'/}"
            [[ -z "${t// /}" || "$t" == \#* ]] && continue
            arr_push cleaned "$t"
        done
        TARGETS=("${cleaned[@]}")
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
            echo -e "${RED}Error: Targets file '$targets_file' contains no usable targets.${NC}"
            exit 1
        fi
    elif [[ -n "$single_target" ]]; then
        arr_push TARGETS "$single_target"
    else
        echo -e "${RED}Error: No targets specified. Use -h for help.${NC}"
        exit 1
    fi

    if [[ "$RESUME_MODE" == true && ! -d "$output_dir" ]]; then
        echo -e "${YELLOW}Warning: --resume was given but output directory '$output_dir' does not exist.${NC}"
        echo -e "${YELLOW}A fresh scan will be started instead.${NC}\n"
    fi

    check_dependencies

    mkdir -p "$output_dir"
    mkdir -p "$output_dir/nmap"

    state_init "$output_dir"

    # Report run time and how to resume if the user aborts the scan.
    trap 'handle_interrupt INT' INT
    trap 'handle_interrupt TERM' TERM

    handle_discord_webhook

    if [ -n "$(opt_get responder_interface)" ]; then
        run_responder "$(opt_get responder_interface)" "$output_dir" &
    fi

    if [[ "${#TARGETS[@]}" -gt 1 ]] || [[ "${TARGETS[0]}" == *"/"* ]]; then
      run_live_host_scans
    else
      printf "%s\n" "${TARGETS[@]}" > "$output_dir/live_hosts.txt"
    fi

    check_for_live_hosts_and_exit

    if opt_true firewall_evasion; then
        echo -e "${YELLOW}Starting Firewall Evasion Scans.${NC}\n"
        run_firewall_evasion_scans "$output_dir"
        echo -e "${BLUE}Firewall evasion scans completed.${NC}"
        finalise_reports
        print_completion_summary
        exit 0
    fi

    echo -e "${YELLOW}Starting Network Penetration Scans.${NC}\n"

    run_nmap_scans "$output_dir"

    if ! opt_true exclude_web_scans; then
        run_web_scans "$output_dir" "${TARGETS[@]}"
    fi

    run_metasploit_scans "$output_dir"

    run_step "smb:smbv1" "SMBv1 check" run_smbv1_scan "$output_dir"

    run_step "smb:unauthrpc" "Unauthenticated RPC check" run_unauth_rpc_scan "$output_dir"

    run_ldap_scan "$output_dir" "${TARGETS[@]}"

    run_dns_scan "$output_dir"

    if opt_true mitm6; then
        run_step "mitm6" "IPv6 DNS takeover test" run_mitm6_scan "$output_dir"
    fi

    if opt_true pret; then
        run_pret_scan "$output_dir"
    fi

    finalise_reports

    mark_completed "scan:finished"

    echo -e "${GREEN}All scans completed. Check the '$output_dir' directory for outputs.${NC}\n"
    print_completion_summary
    echo -e "${GREEN}Happy Hacking! - evan (@evanricafort)${NC}"
}
main "$@"
