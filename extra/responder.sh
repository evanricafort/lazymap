#!/usr/bin/env bash

# extra/responder.sh
# Manages the execution of Responder.

run_responder() {
    local interface="$1"
    local script_path="/usr/share/responder/Responder.py"

    echo -e "${YELLOW}Starting Responder on interface ${interface}...${NC}"
    echo

    # Check if Responder is already running
    if pgrep -f "responder -I $interface" > /dev/null; then
        echo -e "${RED}Responder is already running on interface $interface. Skipping...${NC}"
        return 1
    fi

    # Run Responder in a new screen session to keep it running in the background
    screen -dmS responder bash -c "python3 $script_path -I $interface -wd"

    echo -e "${GREEN}Responder started in a detached screen session. You can reattach with 'screen -r responder'.${NC}"
}