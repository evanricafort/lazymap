#!/bin/bash
# Functions for displaying ASCII art and help messages

display_ascii_art() {
    echo -e "${GREEN}"
    echo " ████                                                                     "
    echo "░░███                                                                     v0.7"
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
    echo -e "${GREEN}Title: lazymap (project0x01)${NC}"
    echo -e "${GREEN}Author: Evan Ricafort (X - @evanricafort | Portfolio - https://evanricafort.com)${NC}"
    echo -e "${GREEN}Description: lazymap is a command-line tool for network penetration testing. it combines multiple selected nmap scripts, sslscan, ssh-audit, dig, ldapsearch, curl, rpcclient, selected metasploit modules, PRET and wget.${NC}"
    echo ""
    echo -e "${BLUE}--Usage--${NC}"
    echo -e "${GREEN}- ./lazymap.sh -u host <options>${NC}"
    echo -e "${GREEN}- ./lazymap.sh -t hosts <options>${NC}"
    echo ""
    echo -e "${BLUE}- Additional options:${NC}"
    echo -e "  ${YELLOW}-1${NC} ${GREEN}for [vulners],${NC}"
    echo -e "  ${YELLOW}-2${NC} ${GREEN}for [vuln],${NC}"
    echo -e "  ${YELLOW}-3${NC} ${GREEN}for both [vulners & vuln] NSE scripts,${NC}"
    echo -e "  ${YELLOW}-4${NC} ${GREEN}for Firewall Evasion Scan,${NC}"
    echo -e "  ${YELLOW}-a${NC} ${GREEN}to exclude the all ports scan and UDP scan.${NC}"
    echo -e "  ${YELLOW}-n${NC} ${GREEN}to add '-n' and '-T4' to nmap command for faster scanning.${NC}"
    echo -e "  ${YELLOW}-k${NC} ${GREEN}to exclude sslscan, ssh-audit, and CheckThatHeaders scans.${NC}"
    echo -e "  ${YELLOW}-b${NC} ${GREEN}to add '-A', '--min-rate 1000' and '--open' for add boost and open ports results only.${NC}"
    echo -e "  ${YELLOW}--pret${NC} ${GREEN}to perform printer security check using PRET (Credits to Jens Mueller).${NC}"
    echo -e "  ${YELLOW}-h${NC} ${GREEN}to display this help message.${NC}"
    echo ""
    echo -e "${GREEN}- Example for additional options: ./lazymap.sh -t hosts -12bank --pret${NC}"
    echo -e "${GREEN}- Reminder: Option -3 may take some time to finish if you have multiple targets.${NC}"
    echo -e "${GREEN}- Note: Run in ${YELLOW}sudo${NC} ${GREEN}mode to execute nmap scripts related to UDP scan.${NC}"
    exit 0
}
