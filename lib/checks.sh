#!/usr/bin/env bash

# lib/help.sh
# Displays the help message.

source "lib/colors.sh"

display_ascii_art() {
    echo -e "${GREEN}"
    echo " ████                                                                     "
    echo "░░███                                                                     v0.8"
    echo " ░███   ██████    █████████ █████ ████ █████████████    ██████   ████████ "
    echo " ░███  ░░░░░███  ░█░░░░███ ░░███ ░███ ░░███░░███░░███  ░░░░░███ ░░███░░███"
    echo " ░███   ███████  ░   ███░   ░███ ░███  ░███ ░███ ░███   ███████  ░███ ░███"
    echo " ░███  ███░░███    ███░   █ ░███ ░███  ░███ ░███ ░███  ███░░███  ░███ ░███"
    echo " █████░░████████  █████████ ░░███████  █████░███ █████░░████████ ░███████ "
    echo "░░░░░  ░░░░░░░░  ░░░░░░░░░   ░░░░░███ ░░░░░ ░░░ ░░░░░  ░░░░░░░░  ░███░░░  "
    echo "                             ███ ░███                            ░███     "
    echo "                            ░░██████                             █████    "
    echo "                             ░░░░░░                             ░░░░░     "
    echo ""
    echo -e "                    ${YELLOW}[network penetration testing kit]${NC}    "
    echo ""
    echo ""
}

display_help() {
    echo -e "${GREEN}Title: lazymap (Project0x01)${NC}"
    echo -e "${GREEN}Author: Evan Ricafort (Email: root@evanricafort.com | X - @evanricafort | Portfolio - https://evanricafort.com)${NC}"
    echo -e "${GREEN}Description: lazymap is a single command-line tool made for network penetration testing. It combines multiple selected NMAP scripts, sslscan, ssh-audit, dig, ldapsearch, curl, rpcclient, selected metasploit modules, PRET and wget.${NC}"
    echo ""
    echo -e "${GREEN}--Usage--${NC}"
    echo -e "${GREEN}- ./lazymap.sh -u host <options>${NC}"
    echo -e "${GREEN}- ./lazymap.sh -t hosts <options>${NC}"
    echo ""
    echo -e "${GREEN}- Additional options:${NC}"
    echo -e "  ${YELLOW}-1${NC} ${GREEN}for [vulners],${NC}"
    echo -e "  ${YELLOW}-2${NC} ${GREEN}for [vuln],${NC}"
    echo -e "  ${YELLOW}-3${NC} ${GREEN}for both [vulners & vuln] NSE scripts,${NC}"
    echo -e "  ${YELLOW}-4${NC} ${GREEN}for Firewall Evasion Scan,${NC}"
    echo -e "  ${YELLOW}-a${NC} ${GREEN}to exclude the all ports scan and UDP scan.${NC}"
    echo -e "  ${YELLOW}-n${NC} ${GREEN}to add '-n' and '-T4' to nmap command for faster scanning.${NC}"
    echo -e "  ${YELLOW}-k${NC} ${GREEN}to exclude sslscan, ssh-audit, and CheckThatHeaders scans.${NC}"
    echo -e "  ${YELLOW}-b${NC} ${GREEN}to add '-A', '--min-rate 1000' and '--open' for add boost and open ports results only.${NC}"
    echo -e "  ${YELLOW}--pret${NC} ${GREEN}to perform printer security check using PRET (Credits to Jens Mueller).${NC}"
    echo -e "  ${YELLOW}--interface [iface]${NC} ${GREEN}to run Responder on a specified interface.${NC}"
    echo -e "  ${YELLOW}-o [dir]${NC} ${GREEN}to specify a custom output directory (default: results).${NC}"
    echo -e "  ${YELLOW}--exclude-udp${NC} ${GREEN}to exclude UDP scan.${NC}"
    echo -e "  ${YELLOW}-h${NC} ${GREEN}to display this help message.${NC}"
    echo ""
    echo -e "${GREEN}- Example: ./lazymap.sh -t hosts -12bank --pret --exclude-udp --interface eth0 -o my_scan${NC}"
    echo ""
    echo -e "${GREEN}- Reminder: Option -3 may take some time to finish if you have multiple targets.${NC}"
    echo -e "${GREEN}- Note: Run in sudo mode to execute NMAP scripts related to UDP scan and Responder.${NC}"
    exit 0
}
