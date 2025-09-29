#!/usr/bin/env bash

# reports/send_discord_webhook.sh
# Sends the HTML report to a specified Discord webhook.

source "lib/colors.sh"

send_discord_webhook() {
    local report_file=$1
    local webhook_url=$2
    local start_date=$3

    if [[ -n "$webhook_url" && -f "$report_file" ]]; then
        echo -e "${YELLOW}Sending report to discord...${NC}\n"

        # Check if curl is installed
        if ! command -v curl &> /dev/null; then
            echo -e "${RED}Error: 'curl' command not found. Please install it to use the Discord webhook feature.${NC}\n"
            return 1
        fi

        # Send the file to the Discord webhook
        curl -X POST -H "Content-Type: multipart/form-data" \
             -F "file=@$report_file" \
             -F "payload_json={\"content\":\"**Lazymap Scan Report**\\nScan started on: \`$start_date\`\"}" \
             "$webhook_url" > /dev/null 2>&1

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Report successfully sent to discord.${NC}\n"
        else
            echo -e "${RED}Failed to send report to Discord. Check your webhook URL and internet connection.${NC}\n"
        fi
    fi
}
