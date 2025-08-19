#!/bin/bash
# Functions for running firewall evasion scans

initialize_firewall_evasion_scripts() {
    FIREWALL_EVASION_SCRIPTS=(
        ["Fragment Packets Result"]='nmap -f -v --reason -oN results/firewallevasion/fragmentpacketsresult.txt'
        ["MTU Result"]='nmap -mtu 16 -v --reason -oN results/firewallevasion/mturesult.txt'
        ["MAC Spoof Apple Result"]='nmap -sT -PO --spoof-mac Apple -Pn -v --reason -oN results/firewallevasion/macspoofappleresult.txt'
        ["MAC Spoof Cisco Result"]='nmap -sT -PO --spoof-mac Cisco -Pn -v --reason -oN results/firewallevasion/macspoofciscoresult.txt'
        ["MAC Spoof Microsoft Result"]='nmap -sT -PO --spoof-mac Microsoft -Pn -v --reason -oN results/firewallevasion/macspoofmicrosoftresult.txt'
        ["MAC Spoof Intel Result"]='nmap -sT -PO --spoof-mac Intel -Pn -v --reason -oN results/firewallevasion/macspoofintelresult.txt'
        ["MAC Spoof Samsung Result"]='nmap -sT -PO --spoof-mac Samsung -Pn -v --reason -oN results/firewallevasion/macspoofsamsungresult.txt'
        ["MAC Spoof Dell Result"]='nmap -sT -PO --spoof-mac Dell -Pn -v --reason -oN results/firewallevasion/macspoofdellresult.txt'
        ["MAC Spoof HP Result"]='nmap -sT -PO --spoof-mac HP -Pn -v --reason -oN results/firewallevasion/macspoofhpresult.txt'
        ["MAC Spoof Sony Result"]='nmap -sT -PO --spoof-mac Sony -Pn -v --reason -oN results/firewallevasion/macspoofsonyresult.txt'
        ["MAC Spoof Netgear Result"]='nmap -sT -PO --spoof-mac Netgear -Pn -v --reason -oN results/firewallevasion/macspoofnetgearresult.txt'
        ["MAC Spoof TP-Link Result"]='nmap -sT -PO --spoof-mac TP-Link -Pn -v --reason -oN results/firewallevasion/macspooftplinkresult.txt'
        ["MAC Spoof ASUS Result"]='nmap -sT -PO --spoof-mac ASUS -Pn -v --reason -oN results/firewallevasion/macspoofasusresult.txt'
        ["MAC Spoof Juniper Result"]='nmap -sT -PO --spoof-mac Juniper -Pn -v --reason -oN results/firewallevasion/macspoofjuniperresult.txt'
        ["MAC Spoof Broadcom Result"]='nmap -sT -PO --spoof-mac Broadcom -Pn -v --reason -oN results/firewallevasion/macspoofbroadcomresult.txt'
        ["Bad Checksum Result"]='nmap --badsum -v --reason -oN results/firewallevasion/badchecksumresult.txt'
        ["Exotic Flag Result"]='nmap -sF -p1-100 -T4 -v --reason -oN results/firewallevasion/exoticflagresult.txt'
        ["Source Port Check Result"]='nmap -sSUC --script source-port -Pn -v --reason -oN results/firewallevasion/sourceportcheckresult.txt'
        ["Source Port Result"]='nmap -g -Pn -v --reason -oN results/firewallevasion/sourceportresult.txt'
        ["ICMP Echo Request Result"]='nmap -n -sn -PE -T4 -v --reason -oN results/firewallevasion/icpmechorequestresult.txt'
        ["Packet Trace Result"]='nmap -vv -n -sn -PE -T4 --packet-trace -v --reason -oN results/firewallevasion/packettracceresult.txt'
    )
    ordered_firewall_evasion_scripts=(
        "Fragment Packets Result" "MTU Result" "MAC Spoof Apple Result" "MAC Spoof Cisco Result"
        "MAC Spoof Microsoft Result" "MAC Spoof Intel Result" "MAC Spoof Samsung Result"
        "MAC Spoof Dell Result" "MAC Spoof HP Result" "MAC Spoof Sony Result" "MAC Spoof Netgear Result"
        "MAC Spoof TP-Link Result" "MAC Spoof ASUS Result" "MAC Spoof Juniper Result"
        "MAC Spoof Broadcom Result" "Bad Checksum Result" "Exotic Flag Result"
        "Source Port Check Result" "Source Port Result" "ICMP Echo Request Result"
        "Packet Trace Result"
    )
}

run_firewall_evasion_scans() {
    local targets_file=$1
    local single_target=$2
    echo -e "${GREEN}Starting Firewall Evasion Scans${NC}\n"
    mkdir -p results/firewallevasion
    for script_name in "${ordered_firewall_evasion_scripts[@]}"; do
        if [[ -n "$targets_file" ]]; then
            echo -e "${GREEN}Starting scan for ${script_name}.${NC}"
            eval "${FIREWALL_EVASION_SCRIPTS[$script_name]} -iL \"$targets_file\""
            echo -e "${GREEN}Completed ${script_name} scan.${NC}\n"
        elif [[ -n "$single_target" ]]; then
            echo -e "${GREEN}Starting scan for ${script_name}.${NC}"
            eval "${FIREWALL_EVASION_SCRIPTS[$script_name]} \"$single_target\""
            echo -e "${GREEN}Completed ${script_name} scan.${NC}\n"
        fi
    done
    echo -e "${BLUE}Firewall evasion scans completed.${NC}"
}