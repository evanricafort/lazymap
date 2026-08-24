#!/usr/bin/env bash

source "$LAZYMAP_DIR/lib/colors.sh"

run_responder() {
    local interface="$1"
    local script_path="/usr/share/responder/Responder.py"

    echo -e "${YELLOW}Starting Responder on interface ${interface}...${NC}"
    echo

    if ! command -v screen &>/dev/null; then
        echo -e "${RED}'screen' is not installed. Skipping Responder.${NC}"
        return 1
    fi

    # Prefer the packaged binary, fall back to the bundled Python script.
    local launch_cmd=""
    if command -v responder &>/dev/null; then
        launch_cmd="responder -I $interface -wd"
    elif [[ -f "$script_path" ]]; then
        launch_cmd="python3 $script_path -I $interface -wd"
    else
        echo -e "${RED}Responder not found (looked for the 'responder' command and $script_path). Skipping.${NC}"
        return 1
    fi

    # Match either launch form so a running instance is detected correctly.
    if pgrep -f "[Rr]esponder(\.py)? .*-I $interface" > /dev/null; then
        echo -e "${RED}Responder is already running on interface $interface. Skipping...${NC}"
        return 1
    fi

    if screen -list 2>/dev/null | grep -q "\.responder[[:space:]]"; then
        echo -e "${RED}A 'responder' screen session already exists. Skipping...${NC}"
        return 1
    fi

    screen -dmS responder bash -c "$launch_cmd"

    echo -e "${GREEN}Responder started in a detached screen session. You can reattach with 'screen -r responder'.${NC}"
}
