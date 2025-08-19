#!/bin/bash
# Functions for checking commands and input validation

check_command() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}Error: $1 is not installed. Please install it before running the script.${NC}"
        exit 1
    fi
}

check_all_commands() {
    check_command "nmap"
    check_command "crackmapexec"
    check_command "ssh-audit"
    check_command "sslscan"
    check_command "wget"
    check_command "dig"
    check_command "ldapsearch"
    check_command "msfconsole"
    check_command "curl"
    check_command "rpcclient"
}

is_subnet() {
    local target=$1
    [[ "$target" == *"/"* ]]
}