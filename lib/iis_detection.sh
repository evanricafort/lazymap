#!/bin/bash

# Function to perform IIS detection
run_iis_detection() {
    echo -e "\n--------------------------------\n"
    echo -e "${YELLOW}Starting Default IIS Webpage scan.${NC}\n"

    found_iis=false

    if [[ -f "results/http.gnmap" ]]; then
        echo -e "${YELLOW}Parsing HTTP Result to find hosts with Microsoft-IIS in Service/Version.${NC}"
        grep -i "Ports:" results/http.gnmap | grep -i "open" | grep -i "Microsoft-IIS" | while read -r line; do
            ip=$(echo "$line" | awk '{print $2}')
            ports_field=$(echo "$line" | sed 's/.*Ports: //')
            IFS=',' read -ra ports_array <<< "$ports_field"
            for port_info in "${ports_array[@]}"; do
                port_info=$(echo "$port_info" | xargs)
                IFS='/' read -ra port_fields <<< "$port_info"
                port_number="${port_fields[0]}"
                state="${port_fields[1]}"
                service="${port_fields[4]}"
                version="${port_fields[5]}"
                service_version="$service $version"
                if [[ "$state" == "open" && "$service_version" == *"Microsoft-IIS"* ]]; then
                    echo -e "${GREEN}Found Microsoft-IIS on $ip:$port_number via service/version.${NC}"
                    if [[ "$found_iis" = false ]]; then
                        mkdir -p results/defaultiis
                        found_iis=true
                    fi
                    output_file="results/defaultiis/defaultiis_${ip}_${port_number}.txt"
                    echo -e "${GREEN}Running curl on $ip:$port_number to get default IIS webpage.${NC}"
                    curl -k -L "$ip:$port_number" -v 2>&1 | tee "$output_file"
                    echo -e "${BLUE}Output saved to $output_file${NC}\n"
                fi
            done
        done
    else
        echo -e "${RED}results/http.gnmap not found. Skipping Microsoft-IIS detection from gnmap.${NC}"
    fi

    if [[ -f "results/http.txt" ]]; then
        echo -e "${YELLOW}Parsing HTTP Result to find hosts with Microsoft-IIS in Server Header.${NC}"
        current_ip=""
        current_port=""
        while IFS= read -r line; do
            if [[ "$line" == "Nmap scan report for "* ]]; then
                current_ip=$(echo "$line" | awk '{print $5}')
            elif [[ "$line" =~ ^[0-9]+/[a-z]+[[:space:]]+open ]]; then
                current_port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
            elif [[ "$line" =~ "Server: Microsoft-IIS" ]]; then
                echo -e "${GREEN}Found Microsoft-IIS on $current_ip:$current_port via Header${NC}"
                if [[ "$found_iis" = false ]]; then
                    mkdir -p results/defaultiis
                    found_iis=true
                fi
                output_file="results/defaultiis/defaultiis_${current_ip}_${current_port}.txt"
                echo -e "${GREEN}Running curl on $current_ip:$current_port to get default IIS webpage.${NC}"
                curl -k -L "$current_ip:$current_port" -v 2>&1 | tee "$output_file"
                echo -e "${BLUE}Output saved to $output_file${NC}\n"
            fi
        done < results/http.txt
    else
        echo -e "${RED}results/http.txt not found. Skipping Microsoft-IIS detection from http.txt.${NC}\n"
    fi

    if [[ "$found_iis" = false ]]; then
        echo -e "${YELLOW}No hosts with Microsoft-IIS found.${NC}\n"
    fi
    echo -e "${BLUE}Default IIS Webpage Detection completed.${NC}"
    echo -e "\n--------------------------------\n"
}
