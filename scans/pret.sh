#!/usr/bin/env bash

source "lib/colors.sh"

run_pret_scan() {
    local output_dir=$1
    echo -e "${YELLOW}Starting PRET for Printer Security Check.${NC}\n"

    local PRET_DIR="$(pwd)/pret_tool"
    local PRET_SCRIPT="$PRET_DIR/pret.py"

    if [[ ! -x "$PRET_SCRIPT" ]]; then
        echo -e "${YELLOW}PRET not found. Installing PRET...${NC}"
        git clone https://github.com/RUB-NDS/PRET.git "$PRET_DIR"
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to clone PRET repository. Please check your internet connection.${NC}"
            exit 1
        fi
        if command -v pip &>/dev/null; then pip install colorama pysnmp; else pip3 install colorama pysnmp; fi
        chmod +x "$PRET_SCRIPT"
        if [[ ! -x "$PRET_SCRIPT" ]]; then
            echo -e "${RED}Failed to install PRET. Please install it manually.${NC}"
            exit 1
        fi
    fi

    echo -e "${GREEN}Starting local printers check.${NC}\n"
    python3 "$PRET_SCRIPT"

    echo -e "${BLUE}Printer security check completed.${NC}\n"
}
