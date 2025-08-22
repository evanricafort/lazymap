#!/bin/bash
# Function to generate an HTML report from scan results

generate_html_report() {
    local target_info=$1
    local timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
    local output_file="results/lazymap_report_${timestamp}.html"

    echo -e "${GREEN}Generating HTML report...${NC}"

    cat > "$output_file" <<EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lazymap Scan Report - ${timestamp}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Source+Code+Pro&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Roboto', sans-serif; background-color: #eef1f5; color: #333; margin: 0; padding: 0; line-height: 1.6; }
        .header { background-color: #2c3e50; color: #ecf0f1; padding: 25px; text-align: center; }
        .header h1 { margin: 0; font-weight: 700; }
        .container { max-width: 1200px; margin: 20px auto; padding: 20px; background: #fff; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        .toc { background-color: #f8f9fa; border: 1px solid #ddd; padding: 15px; border-radius: 6px; margin-bottom: 30px; }
        .toc h2 { margin-top: 0; color: #34495e; }
        .toc ul { list-style-type: none; padding: 0; margin: 0; display: flex; flex-wrap: wrap; }
        .toc li { margin-right: 20px; }
        .toc a { text-decoration: none; color: #3498db; font-weight: bold; }
        .section { margin-bottom: 20px; }
        .section h2 { color: #2980b9; border-bottom: 2px solid #3498db; padding-bottom: 5px; margin-top: 0; }
        details { background-color: #fcfcfc; border: 1px solid #ddd; border-radius: 6px; margin-bottom: 10px; }
        summary { font-size: 1.1em; font-weight: 700; padding: 15px; cursor: pointer; background-color: #f4f6f8; border-radius: 6px; }
        details[open] summary { border-bottom: 1px solid #ddd; }
        pre { font-family: 'Source Code Pro', monospace; background: #2d2d2d; color: #ccc; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em; line-height: 1.4; }
        .result-box { padding: 15px; border-left: 5px solid; border-radius: 5px; margin-top: 10px; }
        .nmap-result { border-color: #27ae60; } /* Green for Nmap */
        .other-result { border-color: #f39c12; } /* Orange for Other */
        .metasploit-result { border-color: #e74c3c; } /* Red for Metasploit */
        .firewall-result { border-color: #8e44ad; } /* Purple for Firewall */
        .pret-result { border-color: #3498db; } /* Blue for PRET */
        .new-scan-result { border-color: #007bff; } /* Blue for new scans */
        footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Lazymap Scan Report</h1>
        <p>A comprehensive report of network penetration tests.</p>
        <p><strong>Generated on:</strong> $(date)</p>
    </div>

    <div class="container">
        <div class="toc">
            <h2>Table of Contents</h2>
            <ul>
                <li><a href="#summary">Summary</a></li>
                <li><a href="#nmap">Nmap Scan Results</a></li>
                <li><a href="#other">Other Scan Results</a></li>
                <li><a href="#new-scans">Specific Vulnerability Scans</a></li>
                <li><a href="#metasploit">Metasploit Scan Results</a></li>
                <li><a href="#firewall">Firewall Evasion Results</a></li>
                <li><a href="#pret">PRET Scan Results</a></li>
            </ul>
        </div>
        
        <div class="section" id="summary">
            <h2>Scan Summary</h2>
            <p><strong>Date:</strong> $(date)</p>
            <p><strong>Target(s):</strong> $target_info</p>
        </div>

        <div class="section" id="nmap">
            <h2>Nmap Scan Results</h2>
            $(awk_nmap_results)
        </div>

        <div class="section" id="other">
            <h2>Other Scan Results</h2>
            $(awk_other_results)
        </div>

        <div class="section" id="metasploit">
            <h2>Metasploit Scan Results</h2>
            $(awk_metasploit_results)
        </div>

        <div class="section" id="firewall">
            <h2>Firewall Evasion Scan Results</h2>
            $(awk_firewall_results)
        </div>

        <div class="section" id="pret">
            <h2>PRET Scan Results</h2>
            $(awk_pret_results)
        </div>

        <div class="section" id="iis-detection">
            <h2>IIS Service Detection</h2>
            $(generate_iis_results)
        </div>

        <div class="section" id="rpc-unauth">
            <h2>RPC Unauthenticated Scan</h2>
            $(generate_rpc_results)
        </div>

        <div class="section" id="ldap-bind">
            <h2>LDAP Anonymous Bind</h2>
            $(generate_ldap_results)
        </div>

        <div class="section" id="dns-vulns">
            <h2>DNS Vulnerabilities Scan</h2>
            $(generate_dns_results)
        </div>

        <div class="section" id="smbv1-detection">
            <h2>SMBv1 Detection</h2>
            $(generate_smbv1_results)
        </div>

        <footer>
            <p>Report generated by Lazymap</p>
        </footer>
    </div>
</body>
</html>
EOL
    echo -e "${GREEN}HTML report saved to $output_file${NC}"
}

# --- Existing functions (retained for clarity) ---
awk_nmap_results() {
    for file in results/*.nmap; do
        if [[ -s "$file" ]]; then
            local filename=$(basename "$file")
            local section_name=$(echo "$filename" | sed 's/\.nmap$//' | sed 's/_/ /g')
            echo "<details><summary>$section_name</summary><div class='result-box nmap-result'><pre>"
            cat "$file"
            echo "</pre></div></details>"
        fi
    done
}

awk_other_results() {
    for file in results/*.txt; do
        if [[ "$file" == *"sslscan"* || "$file" == *"sshaudit"* || "$file" == *"checkthatheader"* ]]; then
            if [[ -s "$file" ]]; then
                local filename=$(basename "$file")
                local section_name=$(echo "$filename" | sed 's/\.txt$//' | sed 's/_/ /g')
                echo "<details><summary>$section_name</summary><div class='result-box other-result'><pre>"
                cat "$file"
                echo "</pre></div></details>"
            fi
        fi
    done
}

awk_metasploit_results() {
    for file in results/*.txt; do
        if [[ "$file" == *"msf"* ]]; then
            if [[ -s "$file" ]]; then
                local filename=$(basename "$file")
                local section_name=$(echo "$filename" | sed 's/\.txt$//' | sed 's/_/ /g')
                echo "<details><summary>$section_name</summary><div class='result-box metasploit-result'><pre>"
                cat "$file"
                echo "</pre></div></details>"
            fi
        fi
    done
}

awk_firewall_results() {
    if [[ -s "results/firewall_evasion_tcp_scan.txt" ]]; then
        echo "<details><summary>TCP Scan</summary><div class='result-box firewall-result'><pre>"
        cat "results/firewall_evasion_tcp_scan.txt"
        echo "</pre></div></details>"
    fi
    if [[ -s "results/firewall_evasion_udp_scan.txt" ]]; then
        echo "<details><summary>UDP Scan</summary><div class='result-box firewall-result'><pre>"
        cat "results/firewall_evasion_udp_scan.txt"
        echo "</pre></div></details>"
    fi
}

awk_pret_results() {
    if [[ -s "results/pret_tool_output.txt" ]]; then
        echo "<details><summary>PRET Scan Output</summary><div class='result-box pret-result'><pre>"
        cat "results/pret_tool_output.txt"
        echo "</pre></div></details>"
    fi
}

# New functions for each module
generate_iis_results() {
    local dir="results/defaultiis"
    if [[ -d "$dir" && $(ls -A "$dir") ]]; then
        find "$dir" -type f | while read -r file; do
            echo "<details><summary>$(basename "$file" | sed 's/\.txt$//')</summary><div class='result-box new-scan-result'><pre>"
            cat "$file"
            echo "</pre></div></details>"
        done
    else
        echo "<p>No hosts with default IIS webpage found.</p>"
    fi
}

generate_rpc_results() {
    local dir="results/unauthrpc"
    if [[ -d "$dir" && $(ls -A "$dir") ]]; then
        find "$dir" -type f | while read -r file; do
            echo "<details><summary>$(basename "$file" | sed 's/\.txt$//')</summary><div class='result-box new-scan-result'><pre>"
            cat "$file"
            echo "</pre></div></details>"
        done
    else
        echo "<p>No unauthenticated RPC connections were successful.</p>"
    fi
}

generate_ldap_results() {
    local dir="results/ldap_anonymous_bind"
    if [[ -d "$dir" && $(ls -A "$dir") ]]; then
        find "$dir" -type f | while read -r file; do
            echo "<details><summary>$(basename "$file" | sed 's/\.txt$//')</summary><div class='result-box new-scan-result'><pre>"
            cat "$file"
            echo "</pre></div></details>"
        done
    else
        echo "<p>No hosts vulnerable to LDAP anonymous bind found.</p>"
    fi
}

generate_dns_results() {
    local dir="results/dnssec"
    if [[ -d "$dir" && $(ls -A "$dir") ]]; then
        find "$dir" -type f | while read -r file; do
            echo "<details><summary>$(basename "$file" | sed 's/\.txt$//')</summary><div class='result-box new-scan-result'><pre>"
            cat "$file"
            echo "</pre></div></details>"
        done
    else
        echo "<p>No DNS vulnerabilities detected or no port 53 open.</p>"
    fi
}

generate_smbv1_results() {
    local file="results/smbv1.txt"
    if [[ -s "$file" ]]; then
        echo "<details><summary>SMBv1 Enabled Hosts</summary><div class='result-box new-scan-result'><pre>"
        cat "$file"
        echo "</pre></div></details>"
    else
        echo "<p>No SMBv1 enabled hosts found.</p>"
    fi
}
