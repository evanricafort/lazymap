#!/usr/bin/env bash

source "$LAZYMAP_DIR/lib/colors.sh"

check_command() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}Error: $1 is not installed. Please install it before running the script.${NC}"
        exit 1
    fi
}

# CrackMapExec was renamed to NetExec (nxc). Accept either.
resolve_crackmapexec() {
    if command -v crackmapexec &>/dev/null; then
        return 0
    elif command -v nxc &>/dev/null; then
        echo -e "${YELLOW}Note: 'crackmapexec' not found, using 'nxc' (NetExec) instead.${NC}"
        crackmapexec() { nxc "$@"; }
        return 0
    fi
    echo -e "${RED}Error: crackmapexec (or nxc) is not installed. Please install it before running the script.${NC}"
    exit 1
}

check_dependencies() {
    check_command "nmap"
    resolve_crackmapexec
    check_command "ssh-audit"
    check_command "sslscan"
    check_command "wget"
    check_command "dig"
    check_command "ldapsearch"
    check_command "msfconsole"
    check_command "curl"
    check_command "rpcclient"
    check_command "screen"
    check_command "zip"
}
