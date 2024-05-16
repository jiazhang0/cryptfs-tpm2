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

# If the luks-setup.sh is called to map a drive before the boot is completed
# manage the resource manager here as needed
RESOURCEMGR_STARTED=0
DEFAULT_ENCRYPTION_NAME="${DEFAULT_ENCRYPTION_NAME:-luks_volume}"
TPM_ABSENT=1
TEMP_DIR=""

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

# Remove the sensitive passphrase in case accidentally terminated
trap_handler() {
    local line_no="$1"
    local err="$2"

    trap - SIGINT EXIT ERR

    print_verbose "Cleaning up ..."
    [ $RESOURCEMGR_STARTED -eq 1 ] && pkill tpm2-abrmd
    [ -n "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"
    unset TPM2TOOLS_DEVICE_FILE TPM2TOOLS_TCTI_NAME TSS2_TCTI

    if [ "$err" != "0" ] && [ "$line_no" != "1" ]; then
        print_error "Error occurred on line $line_no, exit code: $err"
    fi

    exit $err
}

detect_tpm() {
    [ ! -e /sys/class/tpm ] && print_info "TPM subsystem is not enabled" && return 1

    local tpm_devices=$(ls /sys/class/tpm)
    [ -z "$tpm_devices" ] && print_info "No TPM device detected" && return 1

    local tpm_absent=1
    local dev=""
    for dev in $tpm_devices; do
        grep -q "TCG version: 1.2" "/sys/class/tpm/$dev/device/caps" 2>/dev/null &&
            print_warning "TPM 1.2 device is not supported" && break

        grep -q "TPM 2.0 Device" "/sys/class/tpm/$dev/device/description" 2>/dev/null &&
            tpm_absent=0 && break

        # With newer kernel, TPM device description file is renamed
        grep -q "TPM 2.0 Device" "/sys/class/tpm/$dev/device/firmware_node/description" 2>/dev/null &&
            tpm_absent=0 && break

	# With the latest kernel, use tpm_version_major
	grep -q "2" "/sys/class/tpm/$dev/tpm_version_major" 2>/dev/null &&
	    tpm_absent=0 && break

	# Support virtual TPM
	ls "/sys/class/tpm/$dev/device/driver" 2>/dev/null | grep -q MSFT0101 && tpm_absent=0 && break
    done

    [ $tpm_absent -eq 1 ] && print_info "No TPM 2.0 device found" && return 1

    pgrep tpm2-abrmd >/dev/null
    [ $? -ne 0 ] && {
        TPM2TOOLS_TCTI_NAME=device
        TPM2TOOLS_TCTI=device
        export TPM2TOOLS_DEVICE_FILE=/dev/tpmrm0
        TSS2_TCTI=device
    } || {
        TPM2TOOLS_TCTI_NAME=abrmd
        TPM2TOOLS_TCTI=abrmd
        TSS2_TCTI=tabrmd
    }

    export TPM2TOOLS_TCTI_NAME TSS2_TCTI TPM2TOOLS_TCTI

    print_info "TPM 2.0 device \"$dev\" detected"
}

configure_tpm() {
    [ $TPM_ABSENT -eq 1 ] && return 0

    if [ $OPT_EVICT_ALL -eq 1 ]; then
        prompt_info

        local cmd="tpm2_changeauth -c lockout"
        [ -n "$OPT_OLD_LOCKOUT_AUTH" ] && cmd="${cmd} --object-auth=$OPT_OLD_LOCKOUT_AUTH"
        eval "$cmd"
        if [ $? -ne 0 ]; then
            print_error "Failed to clear authorization values with the lockoutAuth specified"
            exit 1
        fi

        # Disable the DA protection. If lockoutAuth fails, the
        # recovery interval is a reboot (_TPM_Init followed by
        # TPM2_Startup).
        cmd="tpm2_dictionarylockout --setup-parameters --max-tries 1 \
             --recovery-time 0 --lockout-recovery-time 0"
        [ -n "$OPT_LOCKOUT_AUTH" ] && cmd="${cmd} $OPT_LOCKOUT_AUTH"
        eval "$cmd"
        if [ $? -ne 0 ]; then
            print_error "Failed to set the default DA policy"
            exit 1
        fi

        if tpm2_getcap handles-persistent | grep -q 0x817FFFFE; then
           print_info "Evicting the passphrase in TPM ..."

           ! cryptfs-tpm2 -q evict passphrase >/dev/null 2>&1 && {
               print_error "Failed to evict the passphrase"
               exit 1
           }

           print_verbose "The passphrase in TPM evicted"
        fi

        if tpm2_getcap handles-persistent | grep -q 0x817FFFFF; then
           print_info "Evicting the primary key in TPM ..."

           ! cryptfs-tpm2 -q evict key >/dev/null 2>&1 && {
               print_error "Failed to evict the primary key"
               exit 1
           }

           print_verbose "The primary key in TPM evicted"
        fi
    fi

    local pcr_opt=""
    [ $OPT_USE_PCR -eq 1 ] && pcr_opt="-P auto"

    if ! tpm2_getcap handles-persistent | grep -q 0x817FFFFF; then
        print_info "Sealing the primary key into TPM ..."

        ! cryptfs-tpm2 -q seal key $pcr_opt && {
            print_error "Unable to seal the primary key"
            exit 1
        }

        print_verbose "The primary key sealed into TPM"
    fi

    if ! tpm2_getcap handles-persistent | grep -q 0x817FFFFE; then
        print_info "Sealing the passphrase into TPM ..."

        ! cryptfs-tpm2 -q seal passphrase $pcr_opt && {
            print_error "Unable to seal the passphrase"
            exit 1
        }

        print_verbose "The passphrase sealed into TPM"
    fi
}

unseal_passphrase() {
    local passphrase=$1
    local err=0
    local pcr_opt=""

    if [ x"$TPM2TOOLS_TCTI_NAME" = x"abrmd" ]; then
        RESOURCEMGR_STARTED=1
        tcti-probe -q wait -d 100 -t 3000 2>/dev/null
        err=$?
    fi

    if [ $err -eq 0 ]; then
        if [ $OPT_USE_PCR -eq 1 ]; then
            pcr_opt="-P auto"
        fi

        ! cryptfs-tpm2 -q unseal passphrase $pcr_opt -o "$passphrase" &&
	    print_error "Unable to unseal the passphrase" && return 1
    else
	print_error "Unable to contact the resource manager" && return 1
    fi

    [ $RESOURCEMGR_STARTED -eq 1 ] && pkill tpm2-abrmd

    print_verbose "Succeed to unseal the passphrase from TPM"
}

is_luks_volume() {
    cryptsetup isLuks "$1"
}

create_luks_volume() {
    local luks_dev="$1"
    local luks_name="$2"
    local passphrase="-"

    print_info "Creating the LUKS volume \"$luks_name\" ..."

    if [ $TPM_ABSENT -eq 0 ]; then
        local pcr_opt=""

        [ $OPT_USE_PCR -eq 1 ] && pcr_opt="-P auto"

        passphrase="$TEMP_DIR/passphrase"
        ! cryptfs-tpm2 -q unseal passphrase $pcr_opt -o "$passphrase" &&
            print_error "Unable to unseal the passphrase" && return 1;
    fi

    if ! cryptsetup --type luks --cipher aes-xts-plain --hash sha256 \
        --use-random --key-file "$passphrase" luksFormat "$luks_dev"; then
        print_error "Unable to create the LUKS volume on $luks_dev"
        return 1
    fi
}

map_luks_volume() {
    local luks_dev="$1"
    local luks_name="$2"
    local passphrase="-"

    if [ -e "/dev/mapper/$luks_name" ]; then
        print_verbose "The LUKS volume \"$luks_name\" already mapped"
        return 0
    fi

    print_info "Mapping the LUKS volume \"$luks_name\" ..."

    if [ $TPM_ABSENT -eq 0 ]; then
        passphrase="$TEMP_DIR/passphrase"

        ! unseal_passphrase "$passphrase" && exit 1
    fi

    if ! cryptsetup luksOpen --key-file "$passphrase" "$luks_dev" "$luks_name"; then
        print_error "Unable to map the LUKS volume \"$luks_name\""
        return 1
    fi
}

unmap_luks_volume() {
    local luks_name="$1"

    if [ ! -e "/dev/mapper/$luks_name" ]; then
        print_verbose "Nothing to unmap"
        return 1
    else
        print_info "Unmapping the LUKS volume \"$luks_name\" ..."

        cryptsetup luksClose "$luks_name" || return $?
    fi

    print_verbose "The LUKS volume \"$luks_name\" unmapped"
}

check_dependencies() {
    local pkg=("cryptsetup" "tpm2-tss" "tpm2-tools")

    print_info "Checking the dependencies ..."

    for p in "${pkg[@]}"; do
        if ! rpm -q "$p" >/dev/null 2>&1; then
            print_info "Installing the package \"$p\" ..."

            local err=`yum install -y "$p"`
            if [ $err -ne 0 ]; then
                print_error "Failed to install the package \"$p\""
                exit $err
            fi
        fi
    done

    print_verbose "The dependencies satisfied"
}

prompt_info() {
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

option_check() {
    if [ -z "$1" ] || echo "$1" | grep -q "^-"; then
        print_error "No value specified for the option $arg"
        exit 1
    fi
}

show_help() {
    cat <<EOF
$PROG_NAME - creation tool for LUKS volume
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

    The default name is $DEFAULT_ENCRYPTION_NAME.

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

PROG_NAME=`basename $0`
OPT_FORCE_CREATION=0
OPT_UNMAP_LUKS=0
OPT_NO_TPM=0
OPT_USE_PCR=0
OPT_EVICT_ALL=0
OPT_VERBOSE=0
OPT_DEBUG=0
# Depreciated
OPT_MAP_EXISTING_LUKS=0
# Depreciated
OPT_NO_SETUP=0
OPT_OLD_LOCKOUT_AUTH=""
OPT_LOUCKOUT_AUTH=""

while [ $# -gt 0 ]; do
    opt=$1
    case $opt in
        -d|--dev)
            shift && option_check $1 && OPT_LUKS_DEV="$1"
            ;;
	-N|--no-setup)
            OPT_NO_SETUP=1
            ;;
	-n|--name)
	    shift && option_check $1 && OPT_LUKS_NAME="$1"
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
            shift && option_check "$1" && OPT_OLD_LOCKOUT_AUTH="$1"
            ;;
        --lockout-auth)
            shift && option_check "$1" && OPT_LOCKOUT_AUTH="$1"
            ;;
	-V|--verbose)
	    OPT_VERBOSE=1
	    ;;
        -D|--debug)
            OPT_DEBUG=1 && set -x
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
            print_error "Unsupported option $opt"
            exit 1
            ;;
    esac
    shift
done

trap 'trap_handler $LINENO $?' SIGINT EXIT ERR

OPT_LUKS_NAME="${OPT_LUKS_NAME:-$DEFAULT_ENCRYPTION_NAME}"

check_dependencies

if [ x"$OPT_LUKS_DEV" = x"" ]; then
    if ! unmap_luks_volume "$OPT_LUKS_NAME"; then
        print_error "LUKS device is not specified"
        exit 1
    fi

    exit 0
elif [ ! -e "$OPT_LUKS_DEV" ]; then
    print_error "Invalid LUKS device specified"
    exit 1
fi

if [ $OPT_NO_TPM -eq 0 ]; then
    if detect_tpm; then
        TPM_ABSENT=0

        ! configure_tpm && exit 1
    fi
fi

TEMP_DIR=`mktemp -d /dev/luks-setup.XXXXXX`
print_verbose "Temporary directory created at \"$TEMP_DIR\""
if [ ! -d "$TEMP_DIR" ]; then
    print_error "Failed to create the temporary directory"
    exit 1
fi

if is_luks_volume "$OPT_LUKS_DEV"; then
    print_info "$OPT_LUKS_DEV is already a LUKS volume"

    if [ $OPT_FORCE_CREATION -eq 0 ]; then
        map_luks_volume "$OPT_LUKS_DEV" "$OPT_LUKS_NAME" && exit 1
        exit 0
    fi

    print_info "Enforce creating the LUKS volume \"$OPT_LUKS_NAME\""
fi

! create_luks_volume "$OPT_LUKS_DEV" "$OPT_LUKS_NAME" && exit 1

! map_luks_volume "$OPT_LUKS_DEV" "$OPT_LUKS_NAME" && exit 1

[ $OPT_UNMAP_LUKS -eq 1 ] && unmap_luks_volume "$OPT_LUKS_NAME"

print_info "The LUKS volume \"$OPT_LUKS_NAME\" backing on $OPT_LUKS_DEV is created"
