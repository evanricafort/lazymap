#!/usr/bin/env bash

source "lib/colors.sh"

send_discord_webhook() {
    local scan_dir=$1
    local webhook_url=$2
    local start_date=$3

    if [[ -n "$webhook_url" && -d "$scan_dir" ]]; then
        echo -e "${YELLOW}Sending report to discord...${NC}\n"

        if ! command -v curl &> /dev/null; then
            echo -e "${RED}Error: 'curl' command not found. Please install it to use the Discord webhook feature.${NC}\n"
            return 1
        fi

        if ! command -v zip &> /dev/null; then
            echo -e "${RED}Error: 'zip' command not found. Please install it to use the Discord webhook feature.${NC}\n"
            return 1
        fi

        local zip_file="${scan_dir%/}.zip"
        zip -r -q "$zip_file" "$scan_dir"

        curl -X POST -H "Content-Type: multipart/form-data" \
             -F "file=@$zip_file" \
             -F "payload_json={\"content\":\"**Lazymap Scan Report**\\nScan started on: \`$start_date\`\"}" \
             "$webhook_url" > /dev/null 2>&1

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Report successfully sent to discord.${NC}\n"
        else
            echo -e "${RED}Failed to send report to Discord. Check your webhook URL and internet connection.${NC}\n"
        fi
    fi
}
