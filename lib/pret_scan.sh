#!/bin/bash
# Function to run PRET printer security check

run_pret_scan() {
    echo -e "${YELLOW}Starting PRET for Printer Security Check.${NC}\n"
    PRET_DIR="$(pwd)/pret_tool"
    PRET_SCRIPT="$PRET_DIR/pret.py"
    if [[ ! -x "$PRET_SCRIPT" ]]; then
        echo -e "${YELLOW}PRET not found. Installing PRET...${NC}"
        git clone https://github.com/RUB-NDS/PRET.git "$PRET_DIR"
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to clone PRET repository. Please check your internet connection and git installation.${NC}"
            exit 1
        fi
        if command -v pip &>/dev/null; then
            pip install colorama pysnmp
        elif command -v pip3 &>/dev/null; then
            pip3 install colorama pysnmp
        else
            echo -e "${RED}pip not found. Cannot install PRET dependencies automatically. Please install pip and try again.${NC}"
            exit 1
        fi
        chmod +x "$PRET_SCRIPT"
        if [[ ! -x "$PRET_SCRIPT" ]]; then
            echo -e "${RED}Failed to install PRET. Please install it manually.${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}Starting local printers check.${NC}\n"
    python3 "$PRET_SCRIPT" > "results/pret_tool/pret_output.txt" 2>&1
    echo -e "${BLUE}Printer security check completed.${NC}"
    echo -e "\n--------------------------------\n"
}