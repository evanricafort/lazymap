#!/usr/bin/env bash

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"
source "$LAZYMAP_DIR/lib/installer.sh"

check_command() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}Error: $1 is not installed. Please install it before running the script.${NC}"
        exit 1
    fi
}

# CrackMapExec was renamed to NetExec, and current distributions ship the
# 'nxc' binary instead. Resolve whichever is present into CME_BIN so callers
# invoke it explicitly rather than relying on a shadowed command name.
CME_BIN=""

resolve_crackmapexec() {
    if command -v crackmapexec &>/dev/null; then
        CME_BIN="crackmapexec"
    elif command -v nxc &>/dev/null; then
        CME_BIN="nxc"
        echo -e "${YELLOW}Note: 'crackmapexec' not found. Using 'nxc' (NetExec), its current name.${NC}"
    fi
}

# Echoes every required tool that is not currently installed.
collect_missing_tools() {
    local tool
    for tool in "${REQUIRED_TOOLS[@]}"; do
        tool_present "$tool" || echo "$tool"
    done
    # Tools for opt-in tests are only required when that test was requested.
    if opt_true mitm6; then
        for tool in "${OPTIONAL_TOOLS[@]}"; do
            tool_present "$tool" || echo "$tool"
        done
    fi
}

report_missing_tools() {
    local missing=("$@")
    echo -e "\n${BLUE}======================================================${NC}"
    echo -e "${RED}Missing dependencies${NC}"
    echo -e "${BLUE}======================================================${NC}"
    local tool
    for tool in "${missing[@]}"; do
        echo -e "${RED}  ✗ $tool${NC}"
    done
    echo -e "${BLUE}======================================================${NC}"
}

check_dependencies() {
    local missing=()
    read_lines_into missing < <(collect_missing_tools)

    if [[ ${#missing[@]} -eq 0 ]]; then
        resolve_crackmapexec
        return 0
    fi

    report_missing_tools "${missing[@]}"

    local do_install=false
    if [[ "$AUTO_INSTALL" == true ]]; then
        do_install=true
    elif [[ "$ASSUME_YES" == true ]]; then
        do_install=true
    elif [[ -t 0 ]]; then
        # Installing packages changes the system, so ask before doing it.
        echo -e "${YELLOW}Install the missing tool(s) now? This runs your package manager with sudo. [y/N]${NC}"
        local reply
        read -r reply
        # Strip carriage returns and surrounding spaces, and accept "yes" too.
        reply="${reply//$'\r'/}"
        reply="${reply#"${reply%%[![:space:]]*}"}"
        reply="${reply%"${reply##*[![:space:]]}"}"
        reply="$(to_lower "$reply")"
        if [ "$reply" = "y" ] || [ "$reply" = "yes" ]; then do_install=true; fi
    else
        echo -e "${YELLOW}Re-run with --install-deps to install them automatically.${NC}"
    fi

    if [[ "$do_install" != true ]]; then
        echo -e "${RED}Cannot continue without the tools listed above.${NC}\n"
        exit 1
    fi

    if ! install_missing_tools "${missing[@]}"; then
        exit 1
    fi

    # Confirm nothing is still missing after the install pass.
    local still_missing=()
    read_lines_into still_missing < <(collect_missing_tools)
    if [[ ${#still_missing[@]} -gt 0 ]]; then
        report_missing_tools "${still_missing[@]}"
        echo -e "${RED}Cannot continue.${NC}\n"
        exit 1
    fi

    resolve_crackmapexec
    echo -e "${GREEN}All dependencies satisfied. Continuing.${NC}\n"
}

# Install dependencies and exit, used by --install-deps with no targets.
run_install_deps_only() {
    local missing=()
    read_lines_into missing < <(collect_missing_tools)

    if [[ ${#missing[@]} -eq 0 ]]; then
        echo -e "${GREEN}All dependencies are already installed. Nothing to do.${NC}\n"
        exit 0
    fi

    report_missing_tools "${missing[@]}"
    install_missing_tools "${missing[@]}" || exit 1

    local still_missing=()
    read_lines_into still_missing < <(collect_missing_tools)
    if [[ ${#still_missing[@]} -gt 0 ]]; then
        report_missing_tools "${still_missing[@]}"
        exit 1
    fi
    echo -e "${GREEN}All dependencies installed.${NC}\n"
    exit 0
}
