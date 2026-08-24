#!/usr/bin/env bash

# lib/installer.sh
# Detects the system package manager and installs missing dependencies.

source "$LAZYMAP_DIR/lib/compat.sh"
source "$LAZYMAP_DIR/lib/colors.sh"

PKG_MGR=""
PKG_INSTALL=""
PKG_REFRESH=""
SUDO=""
AUTO_INSTALL=false
ASSUME_YES=false

# Commands lazymap needs, in the order they are reported.
REQUIRED_TOOLS=(nmap crackmapexec ssh-audit sslscan wget dig ldapsearch msfconsole curl rpcclient screen zip)

detect_pkg_manager() {
    if [[ -n "$PKG_MGR" ]]; then return 0; fi

    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
        PKG_REFRESH="apt-get update"
        PKG_INSTALL="apt-get install -y"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
        PKG_REFRESH=""
        PKG_INSTALL="dnf install -y"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
        PKG_REFRESH=""
        PKG_INSTALL="yum install -y"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
        PKG_REFRESH=""
        PKG_INSTALL="pacman -S --noconfirm --needed"
    elif command -v zypper &>/dev/null; then
        PKG_MGR="zypper"
        PKG_REFRESH=""
        PKG_INSTALL="zypper install -y"
    elif command -v brew &>/dev/null; then
        PKG_MGR="brew"
        PKG_REFRESH=""
        PKG_INSTALL="brew install"
    else
        PKG_MGR="none"
        return 1
    fi
    return 0
}

# Homebrew must not run as root; everything else needs it.
as_root() {
    if [[ "$PKG_MGR" == "brew" ]]; then
        SUDO=""
    elif [[ $EUID -eq 0 ]]; then
        SUDO=""
    elif command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        SUDO=""
        return 1
    fi
    return 0
}

# resolve_package <tool> -> package name for the detected manager,
# "pipx:<name>" for Python tools with no distro package, or "" if unknown.
resolve_package() {
    local tool="$1"

    case "$PKG_MGR" in
        apt)
            case "$tool" in
                dig)          echo "dnsutils" ;;
                ldapsearch)   echo "ldap-utils" ;;
                rpcclient)    echo "smbclient" ;;
                msfconsole)   echo "metasploit-framework" ;;
                crackmapexec) echo "netexec" ;;
                ssh-audit)    echo "ssh-audit" ;;
                *)            echo "$tool" ;;
            esac ;;
        dnf|yum)
            case "$tool" in
                dig)          echo "bind-utils" ;;
                ldapsearch)   echo "openldap-clients" ;;
                rpcclient)    echo "samba-client" ;;
                msfconsole)   echo "" ;;
                crackmapexec) echo "pipx:netexec" ;;
                ssh-audit)    echo "pipx:ssh-audit" ;;
                *)            echo "$tool" ;;
            esac ;;
        pacman)
            case "$tool" in
                dig)          echo "bind" ;;
                ldapsearch)   echo "openldap" ;;
                rpcclient)    echo "smbclient" ;;
                msfconsole)   echo "metasploit" ;;
                crackmapexec) echo "pipx:netexec" ;;
                ssh-audit)    echo "pipx:ssh-audit" ;;
                *)            echo "$tool" ;;
            esac ;;
        zypper)
            case "$tool" in
                dig)          echo "bind-utils" ;;
                ldapsearch)   echo "openldap2-client" ;;
                rpcclient)    echo "samba-client" ;;
                msfconsole)   echo "" ;;
                crackmapexec) echo "pipx:netexec" ;;
                ssh-audit)    echo "pipx:ssh-audit" ;;
                *)            echo "$tool" ;;
            esac ;;
        brew)
            case "$tool" in
                dig)          echo "bind" ;;
                ldapsearch)   echo "openldap" ;;
                rpcclient)    echo "samba" ;;
                msfconsole)   echo "" ;;
                crackmapexec) echo "pipx:netexec" ;;
                ssh-audit)    echo "ssh-audit" ;;
                *)            echo "$tool" ;;
            esac ;;
        *)
            echo "" ;;
    esac
}

# Tools with no automatic recipe get a manual pointer instead of a silent skip.
manual_hint() {
    case "$1" in
        msfconsole) echo "Install the Metasploit Framework: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html" ;;
        *)          echo "No automatic install recipe for '$1' on this system. Please install it manually." ;;
    esac
}

install_via_pipx() {
    local pkg="$1"
    if command -v pipx &>/dev/null; then
        pipx install "$pkg" && return 0
        return 1
    fi
    if command -v pip3 &>/dev/null; then
        # PEP 668 marks system Python as externally managed on newer distros.
        pip3 install --user "$pkg" 2>/dev/null && return 0
        pip3 install --user --break-system-packages "$pkg" && return 0
    fi
    return 1
}

# tool_present <tool> -> honours the crackmapexec/nxc equivalence
tool_present() {
    local tool="$1"
    if [[ "$tool" == "crackmapexec" ]]; then
        command -v crackmapexec &>/dev/null || command -v nxc &>/dev/null
        return $?
    fi
    command -v "$tool" &>/dev/null
}

install_tool() {
    local tool="$1"
    local pkg
    pkg="$(resolve_package "$tool")"

    if [[ -z "$pkg" ]]; then
        echo -e "${YELLOW}  ! $(manual_hint "$tool")${NC}"
        return 1
    fi

    echo -e "${GREEN}  → Installing '$tool'...${NC}"

    if [[ "$pkg" == pipx:* ]]; then
        install_via_pipx "${pkg#pipx:}" || return 1
    else
        # shellcheck disable=SC2086
        $SUDO $PKG_INSTALL "$pkg" || return 1
    fi

    # pipx and pip --user land in ~/.local/bin, which may not be on PATH yet.
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* && -d "$HOME/.local/bin" ]]; then
        export PATH="$HOME/.local/bin:$PATH"
    fi
    hash -r 2>/dev/null

    tool_present "$tool"
}

# install_missing_tools <tool...> -> 0 if everything is present afterwards
install_missing_tools() {
    local missing=("$@")
    [[ ${#missing[@]} -eq 0 ]] && return 0

    if ! detect_pkg_manager; then
        echo -e "${RED}Error: No supported package manager found (apt, dnf, yum, pacman, zypper, brew).${NC}"
        echo -e "${RED}Please install the missing tools manually: ${missing[*]}${NC}"
        return 1
    fi

    if ! as_root; then
        echo -e "${RED}Error: 'sudo' is required to install packages, but it is not available.${NC}"
        echo -e "${RED}Re-run as root, or install manually: ${missing[*]}${NC}"
        return 1
    fi

    echo -e "\n${BLUE}======================================================${NC}"
    echo -e "${GREEN}Installing missing dependencies${NC}"
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${CYAN}Package manager : ${PKG_MGR}${NC}"
    echo -e "${CYAN}Missing tools   : ${missing[*]}${NC}"
    echo -e "${BLUE}======================================================${NC}\n"

    if [[ -n "$PKG_REFRESH" ]]; then
        echo -e "${GREEN}  → Refreshing package lists...${NC}"
        # shellcheck disable=SC2086
        $SUDO $PKG_REFRESH || echo -e "${YELLOW}  ! Package list refresh failed, continuing anyway.${NC}"
    fi

    local installed=() failed=()
    local tool
    for tool in "${missing[@]}"; do
        if install_tool "$tool"; then
            arr_push installed "$tool"
            echo -e "${GREEN}  ✓ '$tool' is now available.${NC}\n"
        else
            arr_push failed "$tool"
            echo -e "${RED}  ✗ Failed to install '$tool'.${NC}\n"
        fi
    done

    echo -e "${BLUE}------------------------------------------------------${NC}"
    [[ ${#installed[@]} -gt 0 ]] && echo -e "${GREEN}Installed : ${installed[*]}${NC}"
    if [[ ${#failed[@]} -gt 0 ]]; then
        echo -e "${RED}Failed    : ${failed[*]}${NC}"
        echo -e "${YELLOW}Install the above manually, then re-run lazymap.${NC}"
        echo -e "${BLUE}------------------------------------------------------${NC}\n"
        return 1
    fi
    echo -e "${BLUE}------------------------------------------------------${NC}\n"
    return 0
}
