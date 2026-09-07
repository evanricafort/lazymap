#!/usr/bin/env bash
#
# lib/state.sh
# Resume state tracking and interrupt handling.
#
# A plain-text state file inside the output directory records every step that
# ran to completion. On --resume those steps are skipped instead of re-run.

STATE_FILE=""
RESUME_MODE=false
# Prefixes of the activity currently running. On an interrupt every completion
# recorded under them is discarded, so the activity restarts from the beginning
# next time rather than resuming half way through.
CURRENT_ACTIVITY=""
INTERRUPTED=false
SKIPPED_STEPS=0

# count_lines_matching <pattern> <file> -> always a bare integer.
# "grep -c" exits 1 when the count is zero, so the common
# "grep -c ... || echo 0" idiom prints "0" twice and breaks arithmetic.
count_lines_matching() {
    local n
    n=$(grep -c "$1" "$2" 2>/dev/null)
    case "$n" in
        ''|*[!0-9]*) n=0 ;;
    esac
    printf '%s' "$n"
}

# Human readable elapsed time since $start_time.
elapsed_runtime() {
    local now diff h m s
    now=$(date +%s)
    diff=$(( now - start_time ))
    h=$(( diff / 3600 ))
    m=$(( (diff % 3600) / 60 ))
    s=$(( diff % 60 ))
    local hu mu su
    (( h == 1 )) && hu="hour" || hu="hours"
    (( m == 1 )) && mu="minute" || mu="minutes"
    (( s == 1 )) && su="second" || su="seconds"
    if (( h > 0 )); then
        printf '%d %s, %d %s and %d %s' "$h" "$hu" "$m" "$mu" "$s" "$su"
    elif (( m > 0 )); then
        printf '%d %s and %d %s' "$m" "$mu" "$s" "$su"
    else
        printf '%d %s' "$s" "$su"
    fi
}

# state_init <output_dir>
state_init() {
    local dir="$1"
    STATE_FILE="$dir/.lazymap_state"

    if [[ "$RESUME_MODE" == true ]]; then
        if [[ ! -f "$STATE_FILE" ]]; then
            echo -e "${YELLOW}No previous state found in '$dir'. Starting a fresh scan.${NC}\n"
            : > "$STATE_FILE"
        else
            local done_count
            done_count=$(count_lines_matching '^done:' "$STATE_FILE")
            echo -e "${BLUE}======================================================${NC}"
            echo -e "${GREEN}Resuming previous scan${NC}"
            echo -e "${CYAN}State file : ${STATE_FILE}${NC}"
            echo -e "${CYAN}Completed  : ${done_count} step(s) will be skipped${NC}"
            local prev
            prev=$(grep '^started:' "$STATE_FILE" 2>/dev/null | tail -n1 | cut -d: -f2-)
            [[ -n "$prev" ]] && echo -e "${CYAN}Original run started: ${prev}${NC}"
            echo -e "${BLUE}======================================================${NC}\n"
        fi
    else
        # Fresh run: any old state is no longer valid for this output directory.
        : > "$STATE_FILE"
    fi

    printf 'started:%s\n' "$start_date" >> "$STATE_FILE"
}

# activity_begin <prefix>...  - marks an activity as in progress
activity_begin() {
    CURRENT_ACTIVITY="$*"
}

activity_end() {
    CURRENT_ACTIVITY=""
}

# Drops every completion belonging to the interrupted activity so that the
# whole activity, not just the item that was running, repeats on --resume.
purge_current_activity() {
    [ -n "$CURRENT_ACTIVITY" ] || return 0
    [ -n "$STATE_FILE" ] && [ -f "$STATE_FILE" ] || return 0

    local prefix
    local removed=0
    for prefix in $CURRENT_ACTIVITY; do
        local before
        local after
        before=$(count_lines_matching "^done:${prefix}" "$STATE_FILE")
        [ "$before" -eq 0 ] && continue
        grep -v "^done:${prefix}" "$STATE_FILE" > "$STATE_FILE.tmp" 2>/dev/null && mv "$STATE_FILE.tmp" "$STATE_FILE"
        after=$(count_lines_matching "^done:${prefix}" "$STATE_FILE")
        removed=$(( removed + before - after ))
    done

    if [ "$removed" -gt 0 ]; then
        echo -e "${CYAN}Discarded ${removed} partial result(s) for the interrupted activity${NC}"
        echo -e "${CYAN}(${CURRENT_ACTIVITY}); it will run again in full on --resume.${NC}"
    fi
    CURRENT_ACTIVITY=""
}

# step_completed <key> -> 0 if the step already finished in a previous run
step_completed() {
    [[ "$RESUME_MODE" == true ]] || return 1
    [[ -n "$STATE_FILE" && -f "$STATE_FILE" ]] || return 1
    grep -Fxq "done:$1" "$STATE_FILE"
}

# mark_completed <key>
mark_completed() {
    [[ -n "$STATE_FILE" ]] || return 0
    grep -Fxq "done:$1" "$STATE_FILE" 2>/dev/null || printf 'done:%s\n' "$1" >> "$STATE_FILE"
}

# skip_notice <key> <label> -- announce a skipped step
skip_notice() {
    SKIPPED_STEPS=$(( SKIPPED_STEPS + 1 ))
    echo -e "${CYAN}↷ Skipping ${2} (already completed in a previous run).${NC}"
}

# run_step <key> <label> <command...>
# Runs the command unless the step is already recorded as complete.
run_step() {
    local key="$1" label="$2"
    shift 2
    if step_completed "$key"; then
        skip_notice "$key" "$label"
        return 0
    fi
    activity_begin "$key"
    "$@"
    local rc=$?
    activity_end
    if [[ "$INTERRUPTED" == true ]]; then
        return "$rc"
    fi
    mark_completed "$key"
    return "$rc"
}

# Interrupt / termination handler.
handle_interrupt() {
    local sig="${1:-INT}"
    # Guard against the handler firing twice.
    [[ "$INTERRUPTED" == true ]] && exit 130
    INTERRUPTED=true

    trap - INT TERM

    echo
    purge_current_activity

    echo -e "\n${BLUE}======================================================${NC}"
    echo -e "${YELLOW}⚠  Scan Interrupted (SIG${sig}) ⚠${NC}"
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${CYAN}Run time before interruption : $(elapsed_runtime)${NC}"
    echo -e "${CYAN}Started at                   : ${start_date}${NC}"
    echo -e "${CYAN}Interrupted at               : $(date)${NC}"
    if [[ -n "$STATE_FILE" && -f "$STATE_FILE" ]]; then
        local done_count
        done_count=$(count_lines_matching '^done:' "$STATE_FILE")
        echo -e "${CYAN}Completed steps saved        : ${done_count}${NC}"
    fi
    echo -e "${CYAN}Partial output directory     : ${output_dir}${NC}"
    echo -e "${BLUE}------------------------------------------------------${NC}"
    echo -e "${GREEN}To continue where this run stopped, re-run the same"
    echo -e "command with --resume and the same output directory:${NC}"
    echo -e "  ${YELLOW}${RESUME_HINT}${NC}"
    echo -e "${BLUE}======================================================${NC}\n"

    # An attack running in a detached screen session outlives this process, so
    # it has to be stopped explicitly before anything else.
    if type mitm6_emergency_stop >/dev/null 2>&1; then
        mitm6_emergency_stop
    fi

    # Stop child processes this script started (nmap, sslscan, ssh-audit, ...).
    pkill -TERM -P $$ 2>/dev/null
    exit 130
}

# Build the command line the user should run to resume.
build_resume_hint() {
    local args=("$@") out="" a
    for a in "${args[@]}"; do
        if [[ "$a" == "--resume" ]]; then continue; fi
        if [[ "$a" =~ [[:space:]] ]]; then
            out="$out '$a'"
        else
            out="$out $a"
        fi
    done
    RESUME_HINT="sudo ./lazymap.sh${out} --resume"
}
