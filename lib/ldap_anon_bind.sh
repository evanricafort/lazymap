#!/bin/bash

# Function to perform LDAP anonymous bind scans
run_ldap_anon_bind() {
    echo -e "\n--------------------------------\n"
    echo -e "${YELLOW}Starting LDAP Anonymous Bind scan.${NC}\n"

    if [[ -f "results/ldap.gnmap" ]]; then
        ldap_ports="389|636|3268|3269"
        awk '/^Host: / && /Ports:.*('"$ldap_ports"')\/open/ {print $2}' results/ldap.gnmap > results/ldap_open_ports.txt

        if [[ -s "results/ldap_open_ports.sh" ]]; then
            echo -e "${GREEN}LDAP ports open found, starting LDAP Anonymous Bind scan.${NC}\n"
            mkdir -p results/ldap_anonymous_bind
            while read -r ip; do
                echo -e "${GREEN}Running LDAP Anonymous Bind scan on $ip${NC}"
                output_file="results/ldap_anonymous_bind/${ip}_ldap_anonymous_bind.txt"
                ldapsearch -v -x -s base -b '' "(objectClass=*)" "*" + -H ldap://$ip | tee "$output_file"
                echo -e "${BLUE}LDAP Anonymous Bind scan for $ip completed and saved to $output_file${NC}\n"
            done < results/ldap_open_ports.sh
            echo -e "${BLUE}LDAP Anonymous Bind Scan Completed.${NC}"
        else
            echo -e "${YELLOW}No LDAP ports open found. Skipping LDAP Anonymous Bind scan.${NC}"
        fi
        rm -f results/ldap_open_ports.sh
    else
        echo -e "${RED}ldap.gnmap not found. Skipping LDAP Anonymous Bind scan.${NC}"
    fi
    echo -e "\n--------------------------------\n"
}
