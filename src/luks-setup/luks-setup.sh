#!/bin/bash

# The wrapper script for the creation of LUKS volume
#
# Copyright (c) 2024, Alibaba Cloud
# Copyright (c) 2016-2023, Wind River Systems, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1) Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2) Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3) Neither the name of Wind River Systems nor the names of its contributors
# may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author:
#        Jia Zhang <zhang.jia@linux.alibaba.com>
#

# Use example:
#   luks-setup.sh -d /dev/sdb1 -n my_luks_volume

VERSION="0.1.0"

# Define the denpendent packages used by this tool
# The "+" prefix means optional package
PACKAGES_DEPENDENT="cryptsetup tpm2-tools tpm2-abrmd procps-ng coreutils gawk grep +cloudbox"

DEFAULT_LUKS_VOLUME_NAME="${DEFAULT_LUKS_VOLUME_NAME:-luks_volume}"
# Prompt the user-supplied passphrase by default
PASSPHRASE="-"
# Don't use cbmkpasswd by default
USE_CBMKPASSWD=0
# Assuming prompting for the passphrase by default
TOKEN_TYPE="luks-setup-prompt"
# Assuming no recovery passphrase by default
RECOVERY_TYPE=""
TEMP_DIR=""
PROG_NAME=`basename $0`
# If luks-setup is called to map a drive before the boot is completed,
# manage the resource manager here as needed
RESOURCEMGR_STARTED=0
TPM2_TOOLS_VERSION="0"
NO_TOKEN_IMPORT=0

# Default option settings

OPT_FORCE_CREATION=0
OPT_UNMAP_LUKS=0
OPT_NO_TPM=0
OPT_USE_PCR=0
OPT_EVICT_ALL=0
OPT_RECOVERY=0
OPT_VERBOSE=0
OPT_DEBUG=0
OPT_INTERACTIVE=0
OPT_OLD_LOCKOUT_AUTH=""
OPT_LOUCKOUT_AUTH=""
# Depreciated
OPT_MAP_EXISTING_LUKS=0
# Depreciated
OPT_NO_SETUP=0

show_help() {
    cat <<EOF
$PROG_NAME - LUKS volume creation tool
Version: $VERSION

(C)Copyright 2024, Alibaba Cloud
(C)Copyright 2016-2023, Wind River Systems, Inc.

Usage: $1 options...

Options:
 -d|--dev <device>
     Set the path to the backing device where the LUKS volume is manipulated.
     e.g, /dev/sda1

 -N|--no-setup
    (Optional) Depreciated. In this mode you can map/unmap existing LUKS volume.

 -n|--name <mapped name>
    (Optional) Set the mapped name for the dmcrypt target device.
    e.g. /dev/mapper/<mapped name>.

    The default name is $DEFAULT_LUKS_VOLUME_NAME.

 -f|--force
    (Optional) Enforce formating the LUKS volume if already existed.

 -m|--map-existing
    (Optional) Depreciated. Map previously created LUKS volume.

 -u|--unmap
    (Optional) Unmap the created LUKS volume before exiting.

 -t|--no-tpm
    (Optional) Don't use TPM.

    By default, TPM is probed automatically.

 -p|--use-pcr
    (Optional) Use PCR to seal/unseal the primary key and passphrase.

 -e|--evict-all
    (Optional) Always evict the primary key and passphrase.

 -r|--recovery
    (Optional) Use the recovery keyslot to unlock the LUKS volume.

 --I|--interactive
    (Optional) Prompt for a user confirmation to format the backing device.

 --old-lockout-auth <old lockoutAuth value>
    (Optional) Special the old lockoutAuth used to clear the old
    authorization values.

 --lockout-auth <new lockoutAuth value>
    (Optional) Set the new lockoutAuth.

 -V|--verbose
    (Optional) Show the verbose output.

 -D|--debug
    (Optional) Enbale the debug.

 --version
    Show the release version.

 -h|--help
    Show this help information.

EOF
}

print_critical() {
    printf "\033[1;35m"
    echo "$@"
    printf "\033[0m"
}

print_error() {
    printf "\033[1;31m"
    echo "$@"
    printf "\033[0m"
}

print_warning() {
    printf "\033[1;33m"
    echo "$@"
    printf "\033[0m"
}

print_info() {
    printf "\033[1;32m"
    echo "$@"
    printf "\033[0m"
}

print_verbose() {
    [ $OPT_VERBOSE -eq 0 ] && return 0

    printf "\033[1;36m"
    echo "$@"
    printf "\033[0m"
}

alert_prompt() {
    echo
    print_critical "******************************************************************"
    print_critical "The primary key and passphrase previously created will be wiped,"
    print_critical "so the data protected by them cannot be restored any more!!!"
    print_critical "Make sure you know what to do before confirming current operation."
    print_critical "******************************************************************"
    echo

    read -p "Do you wish to continue? [y/n] " -n 1
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Installation cancelled"
        exit 0
    else
        print_info "Installation confirmed"
    fi
}

tpm_getcap() {
    local cmd=""

    if [ "$TPM2_TOOLS_VERSION" = "3" ]; then
        cmd="tpm2_getcap --capability=$1"
    elif [ "$TPM2_TOOLS_VERSION" = "4" -o "$TPM2_TOOLS_VERSION" = "5" ]; then
        cmd="tpm2_getcap $1"
    else
        print_error "Unrecognized tpm2-tools version $TPM2_TOOLS_VERSION"
        exit 1
    fi

    eval "$cmd"
}

tpm_takeownership() {
    local cmd=""

    if [ "$TPM2_TOOLS_VERSION" = "3" ]; then
        cmd="tpm2_takeownership --clear"
        [ -n "$OPT_OLD_LOCKOUT_AUTH" ] && cmd="${cmd} --oldLockPasswd=$OPT_OLD_LOCKOUT_AUTH"
    elif [ "$TPM2_TOOLS_VERSION" = "4" -o "$TPM2_TOOLS_VERSION" = "5" ]; then
        cmd="tpm2_changeauth -c lockout"
        [ -n "$OPT_OLD_LOCKOUT_AUTH" ] && cmd="${cmd} --object-auth=$OPT_OLD_LOCKOUT_AUTH"
    else
        print_error "Unrecognized tpm2-tools version $TPM2_TOOLS_VERSION"
        exit 1
    fi

    if ! eval "$cmd"; then
        print_error "[!] Failed to clear authorization values with the lockoutAuth specified"
        return 1
    fi
}

detect_tpm() {
    print_verbose "[?] Detecting TPM 2.0 device ..."

    if [ ! -e "/sys/class/tpm" ]; then
        print_warning "[!] TPM subsystem is not enabled"
        return 1
    fi

    local tpm_devices="$(ls /sys/class/tpm)"
    if [ -z "$tpm_devices" ]; then
        print_warning "[!] Not found any TPM device"
        return 1
    fi

    local tpm_absent=1
    for dev in "$tpm_devices"; do
        if grep -q "TCG version: 1.2" "/sys/class/tpm/$dev/device/caps" 2>/dev/null; then
            print_warning "TPM 1.2 device is not supported"
            break
        fi

        if grep -q "TPM 2.0 Device" "/sys/class/tpm/$dev/device/description" 2>/dev/null; then
            tpm_absent=0
            break
        fi

        # With newer kernel, TPM device description file is renamed
        if grep -q "TPM 2.0 Device" "/sys/class/tpm/$dev/device/firmware_node/description" 2>/dev/null; then
            tpm_absent=0
            break
        fi

        # With the latest kernel, use tpm_version_major to check a TPM 2.0 device
        if grep -q "2" "/sys/class/tpm/$dev/tpm_version_major" 2>/dev/null; then
            tpm_absent=0
            break
        fi

        # Support virtual TPM
        if ls "/sys/class/tpm/$dev/device/driver" 2>/dev/null | grep -q "MSFT0101"; then
            tpm_absent=0
            break
        fi
    done

    if [ $tpm_absent -eq 1 ]; then
        print_info "[!] Not found any TPM 2.0 device"
        return 1
    fi

    if [ -e "/dev/tpmrm0" ]; then
        TPM2TOOLS_TCTI_NAME=device
        TPM2TOOLS_TCTI=device
        TPM2TOOLS_DEVICE_FILE=/dev/tpmrm0
        TSS2_TCTI=device
    elif [ -e "/dev/tpm0" ]; then
        if ! pgrep tpm2-abrmd >/dev/null; then
            systemctl start tpm2-abrmd && RESOURCEMGR_STARTED=1
        fi

        TPM2TOOLS_TCTI_NAME=abrmd
        TPM2TOOLS_TCTI=tabrmd
        TPM2TOOLS_DEVICE_FILE=/dev/tpm0
        TSS2_TCTI=tabrmd
    else
        print_info "[!] Not found any TPM 2.0 device in /dev"
        return 1
    fi

    export TPM2TOOLS_TCTI_NAME TSS2_TCTI TPM2TOOLS_DEVICE_FILE TPM2TOOLS_TCTI

    print_info "[!] Detected TPM 2.0 device \"$dev\""
}

configure_tpm() {
    print_verbose "[?] Configuring TPM 2.0 device ..."

    if [ $OPT_EVICT_ALL -eq 1 ]; then
        alert_prompt

        if ! tpm_takeownership; then
            print_error "[!] Failed to clear authorization values with the lockoutAuth specified"
            return 1
        fi

        # Disable the DA protection. If lockoutAuth fails, the
        # recovery interval is a reboot (_TPM_Init followed by
        # TPM2_Startup).
        cmd="tpm2_dictionarylockout --setup-parameters --max-tries 1 \
             --recovery-time 0 --lockout-recovery-time 0"
        [ -n "$OPT_LOCKOUT_AUTH" ] && cmd="${cmd} $OPT_LOCKOUT_AUTH"
        eval "$cmd"
        if [ $? -ne 0 ]; then
            print_error "[!] Failed to set the default DA policy"
            return 1
        fi

        if tpm_getcap handles-persistent | grep -qi 0x817FFFFE; then
           print_info "Evicting the passphrase in TPM ..."

           ! cryptfs-tpm2 -q evict passphrase && {
               print_error "[!] Failed to evict the passphrase"
               return 1
           }

           print_verbose "The passphrase in TPM evicted"
        fi

        if tpm_getcap handles-persistent | grep -qi 0x817FFFFF; then
           print_info "Evicting the primary key in TPM ..."

           ! cryptfs-tpm2 -q evict key && {
               print_error "[!] Failed to evict the primary key"
               return 1
           }

           print_verbose "The primary key in TPM evicted"
        fi
    fi

    local pcr_opt=""
    [ $OPT_USE_PCR -eq 1 ] && pcr_opt="-P auto"

    if ! tpm_getcap handles-persistent | grep -qi 0x817FFFFF; then
        print_verbose "Sealing the primary key into TPM ..."

        if ! cryptfs-tpm2 -q seal key $pcr_opt; then
            print_error "[!] Unable to seal the primary key"
            return 1
        fi

        print_info "Sealed the primary key into TPM"
    fi

    if ! tpm_getcap handles-persistent | grep -qi 0x817FFFFE; then
        print_info "Sealing the passphrase into TPM ..."

        if ! cryptfs-tpm2 -q seal passphrase $pcr_opt; then
            print_error "[!] Unable to seal the passphrase"
            return 1
        fi

        print_verbose "Sealed the passphrase into TPM"
    fi

    print_info "[!] Configured TPM 2.0 device"
}

retrieve_passphrase() {
    print_verbose "[?] Retrieving the passphrase ..."

    local type="$1"
    if [ "$type" = "luks-setup-deriving" ] || [ "$type" = "luks-setup-deriving-recovery" ]; then
        PASSPHRASE="$TEMP_DIR/passphrase"
        if [ -s "$PASSPHRASE" ]; then
            print_verbose "[!] Skip deriving the passphrase"
            return 0
        fi

        if ! cbmkpasswd -o "$PASSPHRASE"; then
            print_error "[!] Unable to derive the passphrase with cbmkpasswd"
            return 1
        fi

        print_info "[!] Derived the passphrase with cbmkpasswd"

        return 0
    elif [ "$type" = "luks-setup-prompt-recovery" ]; then
        print_info "[!] Skip to automatically retrieve the recovery passphrase"
        return 0
    elif [ "$type" != "luks-setup-unsealing" ]; then
        print_info "[!] Unrecongnized token type \"$type\""
        return 1
    fi

    PASSPHRASE="$TEMP_DIR/passphrase"
    if [ -s "$PASSPHRASE" ]; then
        print_verbose "[!] Use the cached passphrase"
        return 0
    fi

    local err=0
    if [ x"$TPM2TOOLS_TCTI_NAME" = x"abrmd" ]; then
        tcti-probe -q wait -d 100 -t 3000 2>/dev/null
        err=$?
    fi

    if [ $err -eq 0 ]; then
        local pcr_opt=""
        [ $OPT_USE_PCR -eq 1 ] && pcr_opt="-P auto"

        if ! cryptfs-tpm2 -q unseal passphrase $pcr_opt -o "$PASSPHRASE"; then
            print_error "[!] Unable to unseal the passphrase with cryptfs-tpm2"
            return 1
        fi
    else
        print_error "[!] Unable to contact the resource manager"
        return 1
    fi

    [ $RESOURCEMGR_STARTED -eq 1 ] && pkill tpm2-abrmd

    print_info "[!] Unsealed the passphrase from TPM"
}

is_luks_volume() {
    cryptsetup isLuks "$1" >/dev/null 2>&1
}

enroll_token() {
    [ $NO_TOKEN_IMPORT -eq 1 ] && return 0

    local type="$2"
    local desc=""
    local keyslot="0"

    if [ "$type" = "luks-setup-unsealing" ]; then
        desc="unsealed passphrase"
    elif [ "$type" = "luks-setup-deriving" ]; then
        desc="derived passphrase"
    elif [ "$type" = "luks-setup-prompt" ]; then
        desc="prompted passphrase"
    elif [ "$type" = "luks-setup-deriving-recovery" ]; then
        desc="derived passphrase for recovery"
        keyslot="1"
    elif [ "$type" = "luks-setup-prompt-recovery" ]; then
        desc="prompted passphrase for recovery"
        keyslot="1"
    else
        print_error "Unrecognized token type \"$type\""
    fi

    print_verbose "[?] Enrolling a new token for the $desc ..."

    local luks_dev="$1"
    local token="{\"type\":\"$type\",\"keyslots\":[\"$keyslot\"], \"description\": \"$desc\"}"
    if ! echo -n "$token" | cryptsetup token import "$luks_dev"; then
        print_error "[!] Failed to enroll a new token for the $desc"
        return 1
    fi

    print_info "[!] Enrolled the new token for the $desc"
}

create_luks_volume() {
    local luks_name="$2"

    print_info "[?] Creating the LUKS volume \"$luks_name\" ..."

    local type="$3"
    ! retrieve_passphrase "$type" && return $?

    local luks_dev="$1"
    # --type luks means using the default LUKS version choosen by cryptsetup
    local cmd="cryptsetup --type luks --cipher aes-xts-plain64 --hash sha256 \
        --use-random --key-file "$PASSPHRASE" luksFormat "$luks_dev" \
        "

    [ $OPT_INTERACTIVE -eq 0 ] && cmd="$cmd --batch-mode"
    if ! eval "$cmd"; then
        print_error "[!] Unable to create the LUKS volume on $luks_dev"
        return 1
    fi

    # LUKS version 1 doesn't support token
    cryptsetup isLuks --type luks1 "$luks_dev" && NO_TOKEN_IMPORT=1 || {
        if ! enroll_token "$luks_dev" "$type"; then
            print_error "[!] Unable to enroll a new token on the creation for the LUKS volume \"$luks_name\" ..."
            return 1
        fi
    }

    print_info "[!] Created the LUKS volume \"$luks_name\" on the backing device \"$luks_dev\""
}

map_luks_volume() {
    local luks_name="$2"
    local type="$3"

    print_verbose "[?] Mapping the LUKS volume \"$luks_name\" with the token \"$type\" ..."

    if [ -e "/dev/mapper/$luks_name" ]; then
        print_warning "[!] The LUKS volume \"$luks_name\" already mapped"
        return 1
    fi

    ! retrieve_passphrase "$type" && return $?

    local luks_dev="$1"
    if ! cryptsetup luksOpen --key-file "$PASSPHRASE" "$luks_dev" "$luks_name"; then
        print_error "[!] Unable to map the LUKS volume \"$luks_name\" with the token \"$type\""
        return 1
    fi

    print_info "[!] Mapped the LUKS volume \"$luks_name\" with the token \"$type\""
}

unmap_luks_volume() {
    local luks_name="$1"

    print_verbose "[?] Unmapping the LUKS volume \"$luks_name\" ..."

    if [ ! -e "/dev/mapper/$luks_name" ]; then
        print_warning "[!] Nothing to unmap"
        return 1
    fi

    cryptsetup luksClose "$luks_name"
    if [ $? -ne 0 ]; then
        print_error "[!] Failed to unmap the LUKS volume \"$luks_name\""
        return $?
    fi

    print_info "[!] The LUKS volume \"$luks_name\" unmapped"
}

enroll_recovery_keyslot() {
    print_verbose "[?] Enrolling a new keyslot ..."

    local type="$2"
    local passphrase="-"
    if [ "$type" = "luks-setup-deriving-recovery" ]; then
        passphrase="$TEMP_DIR/recovery_passphrase"

        if ! cbmkpasswd -o "$passphrase"; then
            print_error "[!] Unable to derive the passphrase with cbmkpasswd for keyslot enrollment"
            return 1
        fi
    elif [ "$type" != "luks-setup-prompt-recovery" ]; then
        print_error "[!] Unrecognized recovery type \"$type\""
        return 1
    fi

    ! retrieve_passphrase "$type" && return $?

    local luks_dev="$1"
    if ! cryptsetup luksAddKey "$luks_dev" "$passphrase" --key-file "$PASSPHRASE"; then
        print_error "[!] Unable to enroll new keyslot"
        return 1
    fi

    print_info "[!] Enrolled a new keyslot for recovery"
}

enroll_recovery() {
    print_verbose "[?] Enrolling keyslot and token for recovery ..."

    local luks_dev="$1"
    local type="$2"
    if ! enroll_recovery_keyslot "$luks_dev" "$type"; then
        print_error "[!] Failed to enroll a new keyslot for recovery"
        return 1
    fi

    if ! enroll_token "$luks_dev" "$type"; then
        print_error "[!] Unable to enroll a new token for recovery"
        return 1
    fi
}

check_dependencies() {
    print_verbose "[?] Checking the dependencies ..."

    local pkgs=($PACKAGES_DEPENDENT)
    for p in "${pkgs[@]}"; do
        local _p="$p"
        [[ "$p" == +* ]] && _p="${p:1}"

        if ! rpm -q "$_p" >/dev/null 2>&1; then
            print_verbose "Installing the package \"$_p\" ..."

            yum install -y "$_p"
            if [ $? -ne 0 ]; then
                if [ "$_p" != "$p" ]; then
                    print_warning "Skip installing the absent package \"$_p\""
                    continue
                fi

                print_error "[!] Failed to install the package \"$_p\""
                exit 1
            fi
        else
            print_verbose "The package \"$p\" already installed"
        fi
    done

    TPM2_TOOLS_VERSION=$(rpm -q --queryformat "%{VERSION}\n" tpm2-tools | awk -F '.' '{print $1}')
    if [ $? -ne 0 ]; then
        print_error "[!] Failed to get the major version of tpm2-tools"
        exit 1
    fi

    if [ "$TPM2_TOOLS_VERSION" != "3" ] && [ "$TPM2_TOOLS_VERSION" != "4" ] && [ "$TPM2_TOOLS_VERSION" != "5" ]; then
        print_error "[!] Unsupported tpm2-tools version \"$TPM2_TOOLS_VERSION\""
        exit 1
    fi

    local ver="$(cryptsetup --version)"
    local maj=$(echo $ver | awk '{split($2, array, "."); print array[1]}')
    local min=$(echo $ver | awk '{split($2, array, "."); print array[2]}')
    local rev=$(echo $ver | awk '{split($2, array, "."); print array[3]}')

    maj=$((10#$maj))
    min=$((10#$min))
    rev=$((10#$rev))

    if [ $maj -ne 2 ]; then
        print_error "[!] Unsupport cryptsetup version $ver"
        exit 1
    elif [ $min -eq 0 ] && [ $rev -lt 4 ]; then
        NO_TOKEN_IMPORT=1
    fi

    if which cbmkpasswd >/dev/null 2>&1; then
        USE_CBMKPASSWD=1
        print_verbose "Found the cbmkpasswd tool"
    fi

    print_verbose "[!] The dependencies satisfied"
}

option_check() {
    local opt="$1"
    local val="$2"

    if [ -z "$val" ] || echo "$val" | grep -q "^-"; then
        print_error "No value specified for the option $opt"
        exit 1
    fi
}

main() {
    while [ $# -gt 0 ]; do
        local opt="$1"
        case "$opt" in
            -d|--dev)
                shift
                option_check "$opt" "$1"
                OPT_LUKS_DEV="$1"
                ;;
            -N|--no-setup)
                OPT_NO_SETUP=1
                ;;
            -n|--name)
                shift
                option_check "$opt" "$1"
                OPT_LUKS_NAME="$1"
                ;;
            -m|--map-existing)
                OPT_MAP_EXISTING_LUKS=1
                ;;
            -f|--force)
                OPT_FORCE_CREATION=1
                ;;
            -u|--unmap)
                OPT_UNMAP_LUKS=1
                ;;
            -t|--no-tpm)
                OPT_NO_TPM=1
                ;;
            -p|--use-pcr)
                OPT_USE_PCR=1
                ;;
            -e|--evict-all)
                OPT_EVICT_ALL=1
                ;;
            -r|--recovery)
                OPT_RECOVERY=1
                ;;
            -I|--interactive)
                OPT_INTERACTIVE=1
                ;;
            --old-lockout-auth)
                shift
                option_check "$opt" "$1"
                OPT_OLD_LOCKOUT_AUTH="$1"
                ;;
            --lockout-auth)
                shift
                option_check "$opt" "$1"
                OPT_LOCKOUT_AUTH="$1"
                ;;
            -V|--verbose)
                OPT_VERBOSE=1
                ;;
            -D|--debug)
                OPT_DEBUG=1
                set -x
                ;;
            --version)
                print_info "$VERSION"
                exit 0
                ;;
            -h|--help)
                show_help "$PROG_NAME"
                exit 0
                ;;
            *)
                print_error "Unrecognized option $opt"
                exit 1
                ;;
        esac
        shift
    done

    OPT_LUKS_NAME="${OPT_LUKS_NAME:-$DEFAULT_LUKS_VOLUME_NAME}"

    check_dependencies

    if [ $OPT_UNMAP_LUKS -eq 1 ]; then
        unmap_luks_volume "$OPT_LUKS_NAME"
        err=$?
        [ -z "$OPT_LUKS_DEV" ] && exit $err
    fi

    if [ -z "$OPT_LUKS_DEV" ]; then
        [ $OPT_UNMAP_LUKS -eq 1 ] && exit 0

        print_error "A backing device required to be specified with -d/--dev"
        show_help "$PROG_NAME"
        exit 1
    fi

    if [ ! -e "$OPT_LUKS_DEV" ]; then
        print_error "Invalid bakcing device specified with -d/--dev"
        exit 1
    fi

    # Attempt to probe TPM 2.0 device if --no-tpm is not specified
    if [ $OPT_NO_TPM -eq 0 ] && detect_tpm; then
        ! configure_tpm && exit 1

        TOKEN_TYPE="luks-setup-unsealing"
        [ $USE_CBMKPASSWD -eq 1 ] && RECOVERY_TYPE="luks-setup-deriving-recovery" ||
            RECOVERY_TYPE="luks-setup-prompt-recovery"
    else
        [ $OPT_NO_TPM -eq 1 ] && print_info "Skip the detection of TPM 2.0 device"

        # There is no way for recovery in this mode
        if [ $USE_CBMKPASSWD -eq 1 ]; then
            print_info "Prepare to use the cbmkpasswd tool for deriving the passphrase"

            TOKEN_TYPE="luks-setup-deriving"
        else
            print_info "Prepare to prompt for the passphrase"
        fi
    fi

    if [ $OPT_RECOVERY -eq 1 ]; then
        if [ "$RECOVERY_TYPE" = "" ]; then
            print_error "Unable to do the recovery"
            exit 1
        fi

        if [ $NO_TOKEN_IMPORT -eq 0 ] && ! cryptsetup token export --token-id 1 "$OPT_LUKS_DEV" | grep -Eq 'luks-setup-.+-recovery'; then
            print_error "Unable to find the recovery token"
            exit 1
        fi
    fi

    TEMP_DIR="$(mktemp -d /tmp/luks-setup.XXXXXX)"
    print_verbose "Temporary directory created at \"$TEMP_DIR\""
    if [ ! -d "$TEMP_DIR" ]; then
        print_error "Failed to create the temporary directory"
        exit 1
    fi

    if is_luks_volume "$OPT_LUKS_DEV"; then
        print_warning "A LUKS volume backing on \"$OPT_LUKS_DEV\" already existed"

        if [ $OPT_FORCE_CREATION -eq 0 ]; then
            print_info "Skip the creation of LUKS volume unless specifying --force"

            if [ $OPT_RECOVERY -eq 0 ]; then
                map_luks_volume "$OPT_LUKS_DEV" "$OPT_LUKS_NAME" "$TOKEN_TYPE"
            else
                map_luks_volume "$OPT_LUKS_DEV" "$OPT_LUKS_NAME" "$RECOVERY_TYPE"
            fi

            [ $? -ne 0 ] && exit 1

            if [ $OPT_UNMAP_LUKS -eq 1 ]; then
                unmap_luks_volume "$OPT_LUKS_NAME"
            fi
            exit $?
        fi

        print_info "Decide to enforce creating the LUKS volume \"$OPT_LUKS_NAME\""

        if [ -e "/dev/mapper/$OPT_LUKS_NAME" ]; then
            print_error "The mapped LUKS volume \"$OPT_LUKS_NAME\" required to be unmapped first"
            exit 1
        fi
    else
        print_verbose "The backing device \"$OPT_LUKS_DEV\" is not a LUKS volume"
    fi

    ! create_luks_volume "$OPT_LUKS_DEV" "$OPT_LUKS_NAME" "$TOKEN_TYPE" && exit 1

    if [ "$TOKEN_TYPE" = "luks-setup-unsealing" ]; then
        ! enroll_recovery "$OPT_LUKS_DEV" "$RECOVERY_TYPE" && exit $?
    fi

    if [ $OPT_UNMAP_LUKS -eq 0 ]; then
        ! map_luks_volume "$OPT_LUKS_DEV" "$OPT_LUKS_NAME" "$TOKEN_TYPE" && exit 1
    fi

    print_critical "The LUKS volume \"$OPT_LUKS_NAME\" backing on $OPT_LUKS_DEV is created"
}

# Remove the sensitive passphrase in case accidentally terminated
trap_handler() {
    trap - SIGINT EXIT ERR

    local line_no="$1"
    local err=$2

    print_verbose "[?] Cleaning up ..."

    [ $RESOURCEMGR_STARTED -eq 1 ] && pkill tpm2-abrmd
    [ -n "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"

    if [ $err -ne 0 ] && [ "$line_no" != "1" ]; then
        print_error "Error occurred on line $line_no, exit code: $err"
    fi

    print_verbose "[!] Exiting"

    exit $err
}

trap 'trap_handler $LINENO $?' SIGINT EXIT ERR

main "$@"
