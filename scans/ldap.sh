#!/usr/bin/env bash

source "lib/colors.sh"

run_ldap_scan() {
    local output_dir=$1
    echo -e "${YELLOW}Starting LDAP Anonymous Bind scan.${NC}\n"

    if [[ -f "$output_dir/nmap/LDAP.gnmap" ]]; then
        local ldap_ports="389|636|3268|3269"
        awk '/^Host: / && /Ports:.*('"$ldap_ports"')\/open/ {print $2}' "$output_dir/nmap/LDAP.gnmap" > "$output_dir/ldap_open_ports.txt"

        if [[ -s "$output_dir/ldap_open_ports.txt" ]]; then
            mkdir -p "$output_dir/ldap_anonymous_bind"
            while read -r ip; do
                echo -e "${GREEN}Running LDAP Anonymous Bind scan on $ip${NC}"
                ldapsearch -v -x -s base -b '' "(objectClass=*)" "*" + -H ldap://$ip | tee "$output_dir/ldap_anonymous_bind/${ip}.txt"
                echo -e "${BLUE}LDAP Anonymous Bind scan for $ip completed.${NC}\n"
            done < "$output_dir/ldap_open_ports.txt"
        else
            echo -e "${YELLOW}No LDAP ports open found. Skipping LDAP Anonymous Bind scan.${NC}\n"
        fi
    else
        echo -e "${RED}LDAP.gnmap not found. Skipping LDAP Anonymous Bind scan.${NC}\n"
    fi
    echo -e "${BLUE}LDAP Anonymous Bind Scan Completed.${NC}\n"
}
