#!/bin/bash
# Function to execute Responder in a separate screen session

run_responder() {
    local interface=$1
    local script_path="/usr/share/responder/Responder.py"

    echo -e "${GREEN}Starting Responder on interface ${interface}...${NC}"

    # Check if 'screen' is installed
    if ! command -v screen &> /dev/null; then
        echo -e "${RED}Screen is not installed. Please install it to use this feature.${NC}"
        return 1
    fi

    # Check if Responder script exists
    if [[ ! -f "$script_path" ]]; then
        echo -e "${RED}Responder not found at ${script_path}. Please check your installation.${NC}"
        return 1
    fi

    # Check if a screen session named 'responder' already exists
    if screen -list | grep -q "responder"; then
        echo -e "${YELLOW}A screen session named 'responder' is already running. Skipping.${NC}"
        return 0
    fi

    # Start Responder in a new detached screen session
    screen -dmS responder bash -c "python3 $script_path -I $interface -wd"

    echo -e "${GREEN}Responder is now running in a separate session named 'responder'.${NC}"
    echo ""
    echo -e "${BLUE}To attach to the session, run: screen -r responder${NC}"
    echo -e "${BLUE}To detach from the session, press: Ctrl+A then D${NC}"
    echo ""
}