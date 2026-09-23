#!/usr/bin/env bash

# lib/args.sh
# Command line normaliser, replacing GNU getopt.
#
# macOS ships a BSD getopt that cannot parse long options, and Homebrew's
# gnu-getopt is keg-only, so it is absent from the sanitised PATH that sudo
# hands to the script even when it is installed. Parsing here removes the
# dependency entirely and behaves the same everywhere.
#
# normalize_args "$@" fills LZ_ARGS with one option per element, each option
# argument as the following element, then "--", then any operands - the same
# shape "getopt ... | eval set --" produced, so the caller's case loop is
# unchanged.

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"

# Long options that take no argument.
LZ_LONG_NOARG="pret help exclude-udp discord resume install-deps yes mitm6 ntp-dos no-nmap-watchdog"
# Long options that require an argument.
LZ_LONG_ARG="interface domain userlist mitm6-interface mitm6-time script-timeout host-timeout nmap-stall"
# Short options, with and without an argument.
LZ_SHORT_ARG="t u o"
LZ_SHORT_NOARG="1 2 3 4 a n k h b y"

LZ_ARGS=()

lz_in_list() {
    case " $2 " in
        *" $1 "*) return 0 ;;
    esac
    return 1
}

# lz_resolve_long <name> -> sets LZ_RESOLVED to the full option name.
# Exact matches win; otherwise an unambiguous prefix is accepted, as GNU
# getopt does. On failure LZ_RESOLVE_ERR describes why. Results are returned
# in globals rather than printed, because a command substitution would run
# this in a subshell and lose the error.
lz_resolve_long() {
    local want="$1"
    LZ_RESOLVE_ERR=""
    LZ_RESOLVED=""

    if lz_in_list "$want" "$LZ_LONG_NOARG" || lz_in_list "$want" "$LZ_LONG_ARG"; then
        LZ_RESOLVED="$want"
        return 0
    fi

    local match="" count=0 cand
    for cand in $LZ_LONG_NOARG $LZ_LONG_ARG; do
        case "$cand" in
            "$want"*) match="$cand"; count=$(( count + 1 )) ;;
        esac
    done

    if [ "$count" -eq 1 ]; then
        LZ_RESOLVED="$match"
        return 0
    elif [ "$count" -gt 1 ]; then
        LZ_RESOLVE_ERR="ambiguous"
    else
        LZ_RESOLVE_ERR="unknown"
    fi
    return 1
}

lz_arg_error() {
    echo -e "${RED}Error: $1${NC}" >&2
    echo -e "${RED}Run '$(basename "$0") -h' for usage.${NC}" >&2
    exit 1
}

normalize_args() {
    LZ_ARGS=()
    local operands=()
    local no_more_opts=0
    local a name val rest c full

    while [ $# -gt 0 ]; do
        a="$1"

        if [ "$no_more_opts" -eq 1 ]; then
            arr_push operands "$a"
            shift
            continue
        fi

        case "$a" in
            --)
                no_more_opts=1
                shift
                ;;
            --*=*)
                name="${a%%=*}"
                name="${name#--}"
                val="${a#*=}"
                lz_resolve_long "$name" || \
                    lz_arg_error "$LZ_RESOLVE_ERR option '--$name'"
                full="$LZ_RESOLVED"
                if ! lz_in_list "$full" "$LZ_LONG_ARG"; then
                    lz_arg_error "option '--$full' does not take an argument"
                fi
                arr_push LZ_ARGS "--$full" "$val"
                shift
                ;;
            --*)
                name="${a#--}"
                lz_resolve_long "$name" || \
                    lz_arg_error "$LZ_RESOLVE_ERR option '--$name'"
                full="$LZ_RESOLVED"
                if lz_in_list "$full" "$LZ_LONG_ARG"; then
                    if [ $# -lt 2 ]; then
                        lz_arg_error "option '--$full' requires an argument"
                    fi
                    arr_push LZ_ARGS "--$full" "$2"
                    shift 2
                else
                    arr_push LZ_ARGS "--$full"
                    shift
                fi
                ;;
            -?*)
                # A short cluster such as -12bank, or -o dir / -odir.
                rest="${a#-}"
                while [ -n "$rest" ]; do
                    c="${rest%"${rest#?}"}"     # first character
                    rest="${rest#?}"
                    if lz_in_list "$c" "$LZ_SHORT_ARG"; then
                        if [ -n "$rest" ]; then
                            arr_push LZ_ARGS "-$c" "$rest"
                            rest=""
                        else
                            if [ $# -lt 2 ]; then
                                lz_arg_error "option '-$c' requires an argument"
                            fi
                            arr_push LZ_ARGS "-$c" "$2"
                            shift
                        fi
                    elif lz_in_list "$c" "$LZ_SHORT_NOARG"; then
                        arr_push LZ_ARGS "-$c"
                    else
                        lz_arg_error "unknown option '-$c'"
                    fi
                done
                shift
                ;;
            *)
                arr_push operands "$a"
                shift
                ;;
        esac
    done

    arr_push LZ_ARGS "--"
    local op
    for op in ${operands[@]+"${operands[@]}"}; do
        arr_push LZ_ARGS "$op"
    done
}
