#!/usr/bin/env bash

# lib/targets.sh
# Shared target-list builders, so each scan module can source its own targets
# from the nmap output instead of depending on another module having run first.

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"

# collect_smb_targets <output_dir>
# Writes hosts with 139/445 open to <output_dir>/smb_targets.txt.
# Returns 1 when no nmap SMB results are available, 0 otherwise (the file may
# still be empty when nothing was listening).
collect_smb_targets() {
    local output_dir="$1"
    local smb_gnmap="$output_dir/nmap/SMB.gnmap"
    local smb_txt="$output_dir/nmap/SMB.txt"
    local targets="$output_dir/smb_targets.txt"

    # Already built by whichever SMB-based check ran first.
    if [ -s "$targets" ]; then
        return 0
    fi

    if [ -f "$smb_gnmap" ]; then
        awk '/^Host: / && /Ports:.*(139|445)\/open/ {print $2}' "$smb_gnmap" | sort -u > "$targets"
    elif [ -f "$smb_txt" ]; then
        # Fall back to the normal-format output when no greppable file exists.
        awk '/Nmap scan report for/{ip=$NF; gsub(/[()]/,"",ip)} /^(139|445)\/tcp[[:space:]]+open/{print ip}' \
            "$smb_txt" | sort -u > "$targets"
    else
        return 1
    fi

    return 0
}
