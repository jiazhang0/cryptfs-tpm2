#!/bin/bash

# The wrapper script for the creation of LUKS volume
#
# Copyright (c) 2024, Alibaba Cloud
# Copyright (c) 2016-2013, Wind River Systems, Inc.
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
PACKAGES_DEPENDENT="cryptsetup tpm2-tools procps-ng coreutils grep"

DEFAULT_LUKS_VOLUME_NAME="${DEFAULT_LUKS_VOLUME_NAME:-luks_volume}"
# Prompt the user-supplied passphrase by default
PASSPHRASE="-"
# Assuming TPM 2.0 device absent by default
TPM_ABSENT=1
# Don't use cbmkpasswd by default
USE_CBMKPASSWD=0
TEMP_DIR=""
PROG_NAME=`basename $0`
# If luks-setup is called to map a drive before the boot is completed,
# manage the resource manager here as needed
RESOURCEMGR_STARTED=0

# Default option settings

OPT_FORCE_CREATION=0
OPT_UNMAP_LUKS=0
OPT_NO_TPM=0
OPT_USE_PCR=0
OPT_EVICT_ALL=0
OPT_VERBOSE=0
OPT_DEBUG=0
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
     In this mode you can map/unmap existing LUKS volume.

 -n|--name <mapped name>
    (Optional) Set the mapped name for the dmcrypt target device.
    e.g. /dev/mapper/<mapped name>.

    The default name is $DEFAULT_LUKS_VOLUME_NAME.

 -f|--force
    (Optional) Enforce formating the LUKS volume if already existed.

 -m|--map-existing
    (Optional) Map previously created LUKS volume.

 -u|--unmap
    (Optional) Unmap the created LUKS volume before exiting.

 -t|--no-tpm
    (Optional) Don't use TPM.

    By default, TPM is probed automatically.

 -p|--use-pcr
    (Optional) Use PCR to seal/unseal the primary key and passphrase.

 -e|--evict-all
    (Optional) Always evict the primary key and passphrase.

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

    pgrep tpm2-abrmd >/dev/null
    [ $? -ne 0 ] && {
        TPM2TOOLS_TCTI_NAME=device
        TPM2TOOLS_TCTI=device
        TPM2TOOLS_DEVICE_FILE=/dev/tpmrm0
        TSS2_TCTI=device
    } || {
        TPM2TOOLS_TCTI_NAME=abrmd
        TPM2TOOLS_TCTI=abrmd
        TPM2TOOLS_DEVICE_FILE=/dev/tpm0
        TSS2_TCTI=tabrmd
    }

    export TPM2TOOLS_TCTI_NAME TSS2_TCTI TPM2TOOLS_DEVICE_FILE TPM2TOOLS_TCTI

    print_info "[!] Detected TPM 2.0 device \"$dev\""
}

configure_tpm() {
    [ $TPM_ABSENT -eq 1 ] && return 1

    print_verbose "[?] Configuring TPM 2.0 device ..."

    if [ $OPT_EVICT_ALL -eq 1 ]; then
        alert_prompt

        local cmd="tpm2_changeauth -c lockout"
        [ -n "$OPT_OLD_LOCKOUT_AUTH" ] && cmd="${cmd} --object-auth=$OPT_OLD_LOCKOUT_AUTH"
        eval "$cmd"
        if [ $? -ne 0 ]; then
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

        if tpm2_getcap handles-persistent | grep -q 0x817FFFFE; then
           print_info "Evicting the passphrase in TPM ..."

           ! cryptfs-tpm2 -q evict passphrase && {
               print_error "[!] Failed to evict the passphrase"
               return 1
           }

           print_verbose "The passphrase in TPM evicted"
        fi

        if tpm2_getcap handles-persistent | grep -q 0x817FFFFF; then
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

    if ! tpm2_getcap handles-persistent | grep -q 0x817FFFFF; then
        print_verbose "Sealing the primary key into TPM ..."

        if ! cryptfs-tpm2 -q seal key $pcr_opt; then
            print_error "[!] Unable to seal the primary key"
            return 1
        fi

        print_info "Sealed the primary key into TPM"
    fi

    if ! tpm2_getcap handles-persistent | grep -q 0x817FFFFE; then
        print_info "Sealing the passphrase into TPM ..."

        if ! cryptfs-tpm2 -q seal passphrase $pcr_opt; then
            print_error "[!] Unable to seal the passphrase"
            return 1
        fi

        print_verbose "Sealed the passphrase into TPM"
    fi

    print_info "[!] Configured TPM 2.0 device"
}

unseal_passphrase() {
    print_verbose "[?] Unsealing the passphrase ..."

    if [ $USE_CBMKPASSWD -eq 1 ]; then
        PASSPHRASE="$TEMP_DIR/passphrase"

        if ! cbmkpasswd -o "$PASSPHRASE"; then
            print_error "[!] Unable to derive the passphrase with cbmkpasswd"
            return 1
        fi

        print_info "[!] Succeed to derive the passphrase with cbmkpasswd"

        return 0
    fi

    [ $TPM_ABSENT -eq 1 ] && return 0

    PASSPHRASE="$TEMP_DIR/passphrase"

    local err=0
    if [ x"$TPM2TOOLS_TCTI_NAME" = x"abrmd" ]; then
        RESOURCEMGR_STARTED=1
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

    print_info "[!] Succeed to unseal the passphrase from TPM"
}

is_luks_volume() {
    cryptsetup isLuks "$1" >/dev/null 2>&1
}

create_luks_volume() {
    local luks_name="$2"

    print_info "[?] Creating the LUKS volume \"$luks_name\" ..."

    ! unseal_passphrase && return $?

    local luks_dev="$1"
    if ! cryptsetup --type luks --cipher aes-xts-plain64 --hash sha256 \
          --use-random --key-file "$PASSPHRASE" luksFormat "$luks_dev"; then
        print_error "[!] Unable to create the LUKS volume on $luks_dev"
        return 1
    fi

    print_info "[!] Created the LUKS volume \"$luks_name\" on the backing device \"$luks_dev\""
}

map_luks_volume() {
    local luks_name="$2"

    print_verbose "[?] Mapping the LUKS volume \"$luks_name\" ..."

    if [ -e "/dev/mapper/$luks_name" ]; then
        print_warning "[!] The LUKS volume \"$luks_name\" already mapped"
        return 1
    fi

    ! unseal_passphrase && return $?

    local luks_dev="$1"
    if ! cryptsetup luksOpen --key-file "$PASSPHRASE" "$luks_dev" "$luks_name"; then
        print_error "[!] Unable to map the LUKS volume \"$luks_name\""
        return 1
    fi

    print_info "[!] Mapped the LUKS volume \"$luks_name\""
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

check_dependencies() {
    print_verbose "[?] Checking the dependencies ..."

    local pkgs=($PACKAGES_DEPENDENT)
    for p in "${pkgs[@]}"; do
        if ! rpm -q "$p" >/dev/null 2>&1; then
            print_verbose "Installing the package \"$p\" ..."

            yum install -y "$p"
            if [ $? -ne 0 ]; then
                print_error "[!] Failed to install the package \"$p\""
                exit 1
            fi
        else
            print_verbose "The package \"$p\" already installed"
        fi
    done

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
        exit 1
    elif [ ! -e "$OPT_LUKS_DEV" ]; then
        print_error "Invalid bakcing device specified with -d/--dev"
        exit 1
    fi

    # Attempt to probe TPM 2.0 device if --no-tpm is not specified
    if [ $OPT_NO_TPM -eq 0 ]; then
        if detect_tpm; then
            TPM_ABSENT=0
            # Forcefully forbid the execution of the cbmkpasswd tool
            USE_CBMKPASSWD=0

            ! configure_tpm && exit 1
        fi
    else
        print_info "Skip the detection of TPM 2.0 device"

        [ $USE_CBMKPASSWD -eq 1 ] && print_info "Use the cbmkpasswd instead" ||
            print_info "Prepare to prompt for the passphrase instead"
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

            map_luks_volume "$OPT_LUKS_DEV" "$OPT_LUKS_NAME"
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

    ! create_luks_volume "$OPT_LUKS_DEV" "$OPT_LUKS_NAME" && exit 1

    if [ $OPT_UNMAP_LUKS -eq 0 ]; then
        ! map_luks_volume "$OPT_LUKS_DEV" "$OPT_LUKS_NAME" && exit 1
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
