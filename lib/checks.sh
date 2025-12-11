#!/usr/bin/env bash

source "lib/colors.sh"

check_command() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}Error: $1 is not installed. Please install it before running the script.${NC}"
        exit 1
    fi
}

check_dependencies() {
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
    check_command "screen"
    check_command "zip"
}
