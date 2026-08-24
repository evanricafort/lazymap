#!/usr/bin/env bash

# lib/domain.sh
# Recovers the Active Directory realm from scan output. Shared by the Kerberos
# username enumeration module and the mitm6 IPv6 DNS takeover test.

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"

# resolve_ad_domain <output_dir> -> realm in uppercase, or empty
resolve_ad_domain() {
    local output_dir="$1"
    local domain

    domain="$(opt_get kerberos_domain)"
    if [ -n "$domain" ]; then
        to_upper "$domain"
        return 0
    fi

    # Recover the realm from the LDAP rootDSE naming context.
    if [ -f "$output_dir/nmap/LDAP.txt" ]; then
        # Turn the comma-separated DC components into a dotted realm. The label
        # is stripped first: a greedy .*DC= would match the last component and
        # drop everything before it.
        domain=$(grep -iaoE '(default|rootDomain)NamingContext: *DC=[^ ]+' "$output_dir/nmap/LDAP.txt" \
                 | head -n1 \
                 | sed -E 's/^.*[Nn]aming[Cc]ontext: *//' \
                 | sed -E 's/[Dd][Cc]=//g' \
                 | tr ',' '.' | tr -d '\r')
        if [ -n "$domain" ]; then
            to_upper "$domain"
            return 0
        fi
    fi

    # Fall back to the domain name reported by smb-os-discovery or nbstat.
    local f
    for f in "$output_dir/nmap/SMB.txt" "$output_dir/nmap/NetBIOS.txt" "$output_dir/nmap/Kerberos.txt"; do
        [ -f "$f" ] || continue
        domain=$(grep -iaoE 'Domain name: *[A-Za-z0-9._-]+' "$f" | head -n1 \
                 | sed -E 's/.*: *//' | tr -d '\r')
        # nmap prints "<unknown>" when it could not determine the domain.
        case "$domain" in ''|'<unknown>'|unknown) domain="" ;; esac
        if [ -n "$domain" ]; then
            to_upper "$domain"
            return 0
        fi
    done

    printf ''
}

