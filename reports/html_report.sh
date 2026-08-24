#!/usr/bin/env bash

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"

report_row() {
    local scan_name="$1"
    local file_path="$2"
    local summary_text="$3"
    local status="Failed or No Findings"
    local status_color="red"

    if [[ -d "$file_path" && -n "$(find "$file_path" -type f -print -quit)" ]]; then
        status="Completed"
        status_color="green"
    elif [[ -f "$file_path" && -s "$file_path" ]]; then
        status="Completed"
        status_color="green"
    elif [[ -f "$file_path" ]]; then
        status="Empty/No Findings"
        status_color="orange"
        summary_text="No key findings detected."
    fi

    echo "<tr><td>$scan_name</td><td style=\"color:$status_color;\">$status</td><td>$summary_text</td></tr>"
}

html_escape() {
    sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

create_collapsible_section() {
    local title="$1"
    local path="$2"
    local glob_pattern="${3:-*}"

    if [[ -d "$path" ]]; then
        local files_found=false
        printf '<details><summary>%s</summary><pre>' "$title"
        while IFS= read -r file; do
            [[ -f "$file" ]] || continue
            printf -- '---- File: %s ----\n' "$(basename "$file")"
            html_escape < "$file"
            printf '\n\n'
            files_found=true
        done < <(find "$path" -type f -name "$glob_pattern" | sort)
        [[ "$files_found" == false ]] && printf 'No files found in this directory.\n'
        printf '</pre></details>\n'
    elif [[ -f "$path" ]]; then
        printf '<details><summary>%s</summary><pre>' "$title"
        html_escape < "$path"
        printf '</pre></details>\n'
    fi
}

create_individual_file_sections() {
    local path="$1"
    local glob_pattern="$2"

    if [[ -d "$path" ]]; then
        # Check if any files exist before starting loop
        if [[ -z "$(find "$path" -type f -name "$glob_pattern" -print -quit)" ]]; then
             echo "<p class='note'>No files found in this directory.</p>"
             return
        fi

        # Iterate through files individually
        while read -r file; do
            local filename=$(basename "$file")

            echo "<details>"
            echo "<summary>$filename</summary>"
            echo "<pre>"
            # Escape HTML characters to treat output as RAW text and prevent macro/script execution
            sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$file"
            echo "</pre>"
            echo "</details>"
        done < <(find "$path" -type f -name "$glob_pattern" | sort)
    else
        echo "<p class='note'>Directory not found: $path</p>"
    fi
}

generate_html_report() {
    local output_dir=$1
    local start_date=$2
    local end_date=$3

    echo -e "${YELLOW}Generating HTML report...${NC}\n"

    report_file="$output_dir/lazymap_report.html"

    cat > "$report_file" <<- EOM
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lazymap Scan Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f4f7f9; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        .metadata table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        .metadata th, .metadata td { text-align: left; padding: 8px; border: 1px solid #ddd; }
        .metadata th { background-color: #ecf0f1; }
        .scan-results table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
        .scan-results th, .scan-results td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        .scan-results th { background-color: #3498db; color: #fff; }
        .scan-results tr:nth-child(even) { background-color: #f9f9f9; }
        .scan-results td:first-child { font-weight: bold; }
        pre { background: #ecf0f1; padding: 15px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }
        .note { color: #7f8c8d; font-style: italic; }
        details { background: #e9ecef; border: 1px solid #ccc; border-radius: 5px; margin-bottom: 10px; }
        summary { cursor: pointer; padding: 10px; background: #d0d8e0; border-bottom: 1px solid #ccc; font-weight: bold; }
        details pre { margin: 0; padding: 15px; background: #f4f7f9; }
        .search-container {
            position: sticky;
            top: 0;
            background-color: #f4f7f9;
            padding: 10px 0;
            z-index: 1000;
            border-bottom: 1px solid #ddd;
        }
        #searchInput { width: 100%; padding: 10px; box-sizing: border-box; font-size: 16px; border: 1px solid #ccc; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Lazymap - Network Penetration Testing Kit</h1>
        <div class="metadata">
            <h2>Scan Details</h2>
            <table>
                <tr><th>Report Title</th><td>Lazymap Scan Report</td></tr>
                <tr><th>Start Date & Time</th><td>$start_date</td></tr>
                <tr><th>End Date & Time</th><td>$end_date</td></tr>
                <tr><th>Live Host(s) Found</th><td>
$(
    if [[ -s "$output_dir/live_hosts.txt" ]]; then
        awk '{print "<span>" $0 "</span><br>"}' "$output_dir/live_hosts.txt"
    else
        echo "<span style=\"color:#c0392b;\">None - no live hosts were found in the defined target scope.</span>"
    fi
)
                </td></tr>
                <tr><th>Host Count</th><td>
$(
    if [[ -s "$output_dir/live_hosts.txt" ]]; then
        grep -c . "$output_dir/live_hosts.txt"
    else
        echo "0"
    fi
)
                </td></tr>
            </table>
        </div>

        <div class="scan-results">
            <h2>Scan Results Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>Scan Type</th>
                        <th>Status</th>
                        <th>Summary / Key Findings</th>
                    </tr>
                </thead>
                <tbody>
$(
    report_row "Nmap Scan" "$output_dir/nmap/TCP.txt" "General TCP and port scans."
    report_row "SSLScan" "$output_dir/sslscan" "SSL/TLS configurations and vulnerabilities."
    report_row "SSH-Audit" "$output_dir/sshaudit" "SSH server security audit."
    report_row "CrackMapExec (SMBv1)" "$output_dir/smbv1.txt" "Detection of SMBv1 enabled hosts."
    report_row "LDAP Anonymous Bind" "$output_dir/ldap_anonymous_bind" "Results of anonymous bind attempts."
    report_row "DNS Vulnerabilities" "$output_dir/dnssec" "DNSSec and recursion tests."
    report_row "IPv6 DNS Takeover (mitm6)" "$output_dir/mitm6" "DHCPv6/DNS spoofing and NTLM relay results."
    report_row "Printer Security (PRET)" "$output_dir/pret" "Printer discovery and exposure check."
    report_row "Unauthenticated RPC" "$output_dir/unauthrpc" "Results of unauthenticated RPC connections."
    report_row "Metasploit - RDP" "$output_dir/msfrdp" "RDP scan outputs."
    report_row "Metasploit - RPC" "$output_dir/msfrpc" "RPC scan outputs."
    report_row "Metasploit - Oracle" "$output_dir/msforacletnscmd" "Oracle database scan outputs."
    report_row "Metasploit - AFP" "$output_dir/msfafp" "AFP scan outputs."
    report_row "Metasploit - NTP" "$output_dir/msfntp" "NTP scan outputs."
    report_row "Metasploit - SNMP" "$output_dir/msfsnmp" "SNMP scan outputs."
    report_row "Metasploit - Kerberos" "$output_dir/msfkerberos" "Kerberos domain username enumeration."
)
                </tbody>
            </table>
        </div>

        <div class="raw-data">
            <h2>Raw Scan Outputs</h2>
            <div class="note">Each section below contains the raw output from the corresponding tool. Click to expand.</div>

            <div class="search-container">
                <input type="text" id="searchInput" onkeyup="searchFunction()" placeholder="Search for exact keywords...">
            </div>

            <script>
            function searchFunction() {
                var input, filter, rawData, details, summary, pre, i;
                input = document.getElementById('searchInput');
                filter = input.value.toLowerCase().split(' ').filter(word => word.length > 0);
                rawData = document.querySelector('.raw-data');
                details = rawData.getElementsByTagName('details');

                if (filter.length === 0) {
                    for (i = 0; i < details.length; i++) {
                        details[i].style.display = "";
                    }
                    return;
                }

                for (i = 0; i < details.length; i++) {
                    summary = details[i].getElementsByTagName('summary')[0];
                    pre = details[i].getElementsByTagName('pre')[0];
                    var content = (summary.textContent || summary.innerText) + " " + (pre.textContent || pre.innerText);
                    var allKeywordsFound = filter.every(keyword => content.toLowerCase().includes(keyword));

                    if (allKeywordsFound) {
                        details[i].style.display = "";
                    } else {
                        details[i].style.display = "none";
                    }
                }
            }
            </script>

$(
    echo "<h3>Nmap Scan Outputs</h3>"
    create_individual_file_sections "$output_dir/nmap" "*.txt"

    echo "<h3>Metasploit Scan Outputs</h3>"
    create_collapsible_section "Metasploit - RDP" "$output_dir/msfrdp" "*.txt"
    create_collapsible_section "Metasploit - RPC" "$output_dir/msfrpc" "*.txt"
    create_collapsible_section "Metasploit - Oracle" "$output_dir/msforacletnscmd" "*.txt"
    create_collapsible_section "Metasploit - AFP" "$output_dir/msfafp" "*.txt"
    create_collapsible_section "Metasploit - NTP" "$output_dir/msfntp" "*.txt"
    create_collapsible_section "Metasploit - SNMP" "$output_dir/msfsnmp" "*.txt"
    create_collapsible_section "Metasploit - Kerberos" "$output_dir/msfkerberos" "*.txt"

    echo "<h3>Web Scan Outputs</h3>"
    create_collapsible_section "SSLScan" "$output_dir/sslscan" "*.txt"
    create_collapsible_section "SSH-Audit" "$output_dir/sshaudit" "*.txt"

    echo "<h3>SMB & RPC Scan Outputs</h3>"
    create_collapsible_section "CrackMapExec (SMBv1)" "$output_dir/smbv1.txt"
    create_collapsible_section "Unauthenticated RPC" "$output_dir/unauthrpc" "*.txt"

    echo "<h3>LDAP Scan Outputs</h3>"
    create_collapsible_section "LDAP Anonymous Bind" "$output_dir/ldap_anonymous_bind" "*.txt"

    echo "<h3>DNS Scan Outputs</h3>"
    create_collapsible_section "DNS Vulnerabilities" "$output_dir/dnssec" "*.txt"

    echo "<h3>Printer Security (PRET)</h3>"
    create_collapsible_section "PRET" "$output_dir/pret" "*.txt"

    echo "<h3>IPv6 DNS Takeover (mitm6)</h3>"
    create_collapsible_section "mitm6 - relayed accounts" "$output_dir/mitm6/relayed_accounts.txt"
    create_collapsible_section "mitm6 - ntlmrelayx log" "$output_dir/mitm6/ntlmrelayx.log"
    create_collapsible_section "mitm6 - mitm6 log" "$output_dir/mitm6/mitm6.log"
    create_collapsible_section "mitm6 - loot" "$output_dir/mitm6/loot" "*"
)
        </div>
    </div>
</body>
</html>
EOM

    echo -e "${BLUE}HTML report generated at $report_file.${NC}"
}
