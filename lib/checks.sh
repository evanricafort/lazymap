#!/usr/bin/env bash

source "$LAZYMAP_DIR/lib/colors.sh"

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
    else
        echo -e "${RED}Error: crackmapexec is not installed. Please install it before running the script.${NC}"
        echo -e "${RED}       It is now distributed as NetExec - 'pipx install netexec' provides the 'nxc' command.${NC}"
        exit 1
    fi
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
