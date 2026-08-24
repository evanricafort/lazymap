#!/usr/bin/env bash

# lib/compat.sh
# Portability helpers so lazymap runs on Bash 3.x (including the 3.2 that
# ships with macOS) as well as Bash 4 and 5. Nothing here may use
# associative arrays, mapfile/readarray, namerefs, ${var,,}/${var^^},
# or the += append operator.

# read_lines_into <array_name>
# Reads stdin, one element per line, into the named array. Replaces
# "mapfile -t <name>". A trailing line with no newline is still captured.
read_lines_into() {
    local __name="$1"
    local __line
    local __i=0
    eval "$__name=()"
    while IFS= read -r __line || [ -n "$__line" ]; do
        eval "$__name[\$__i]=\$__line"
        __i=$(( __i + 1 ))
    done
}

# arr_push <array_name> <value>...
# Appends to an indexed array without using "+=".
arr_push() {
    local __name="$1"
    shift
    local __i
    local __v
    for __v in "$@"; do
        eval "__i=\${#$__name[@]}"
        eval "$__name[\$__i]=\$__v"
    done
}

# str_append <var_name> <text>
# Appends to a scalar without using "+=".
str_append() {
    local __name="$1"
    eval "$__name=\${$__name}\$2"
}

# to_lower <string> -> lowercase, without ${var,,}
to_lower() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# ---------------------------------------------------------------------------
# Option store
#
# Replaces "declare -A OPTIONS". Keys are stored as individual variables named
# __LZOPT_<key>, so no associative array support is required.
# ---------------------------------------------------------------------------

opt_set() {
    eval "__LZOPT_$1=\$2"
}

opt_get() {
    eval "printf '%s' \"\${__LZOPT_$1-}\""
}

opt_true() {
    local __v
    eval "__v=\${__LZOPT_$1-}"
    [ "$__v" = "true" ]
}

opt_unset() {
    unset "__LZOPT_$1"
}

# ---------------------------------------------------------------------------
# Ordered name -> value tables
#
# Replaces the associative arrays used for the nmap script tables. Entries are
# held in a plain indexed array as "name<TAB>value", which keeps insertion
# order and needs no Bash 4 features. Values never contain a tab.
# ---------------------------------------------------------------------------

LZ_TAB=$(printf '\t')

# table_add <table_name> <key> <value>
table_add() {
    local __t="$1"
    arr_push "$__t" "$2$LZ_TAB$3"
}

# table_key <entry> -> the key part of an entry
table_key() {
    printf '%s' "${1%%$LZ_TAB*}"
}

# table_value <entry> -> the value part of an entry
table_value() {
    printf '%s' "${1#*$LZ_TAB}"
}
