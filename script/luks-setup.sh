#!/bin/sh

# The wrapper script for the creation of LUKS partition
#
# BSD 2-clause "Simplified" License
#
# Copyright (c) 2016-2017, Lans Zhang <jia.zhang@windriver.com>, Wind River Systems, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Author:
#      Lans Zhang <jia.zhang@windriver.com>
#

# Use example:
#   luks-setup.sh -d /dev/sdb1 -n my_luks_part

VERSION="0.1.0"

# If the luks-setup.sh is called to map a drive before the boot is completed
# manage the resourcemgr here as needed
RESOURCEMGR_STARTED=0
DEFAULT_ENCRYPTION_NAME="${DEFAULT_ENCRYPTION_NAME:-luks_part}"
TPM_ABSENT=1
TEMP_DIR=""

function print_critical()
{
    printf "\033[1;35m"
    echo "$@"
    printf "\033[0m"
}

function print_error()
{
    printf "\033[1;31m"
    echo "$@"
    printf "\033[0m"
}

function print_warning()
{
    printf "\033[1;33m"
    echo "$@"
    printf "\033[0m"
}

function print_info()
{
    printf "\033[1;32m"
    echo "$@"
    printf "\033[0m"
}

function print_verbose()
{
    [ $OPT_VERBOSE -eq 0 ] && return 0

    printf "\033[1;36m"
    echo "$@"
    printf "\033[0m"
}

# Remove the sensitive passphrase in case accidentally terminated
function trap_handler()
{
    print_verbose "Cleaning up ..."
    [ $RESOURCEMGR_STARTED -eq 1 ] && pkill resourcemgr
    [ -n "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"
}

function detect_tpm()
{
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
    done

    [ $tpm_absent -eq 1 ] && print_info "No TPM device found" && return 1

    print_info "TPM device /dev/$dev detected"

    return 0
}

function unseal_passphrase()
{
    local passphrase=$1

    if ! pgrep resourcemgr > /dev/null; then
        (! /usr/sbin/resourcemgr >/dev/null 2>&1) &
        RESOURCEMGR_STARTED=1
        sleep 0.1
    fi

    ! cryptfs-tpm2 -q unseal passphrase -P auto -o "$passphrase" &&
        print_error "Unable to unseal the passphrase" && return 1

    [ $RESOURCEMGR_STARTED -eq 1 ] && pkill resourcemgr

    return 0
}

function is_luks_partition()
{
    cryptsetup isLuks "$1"
}

function create_luks_partition()
{
    local luks_dev="$1"
    local luks_name="$2"
    local tpm_absent="$3"
    local tmp_dir="$4"
    local passphrase="-"

    print_info "Creating the LUKS partition $luks_name ..."

    if [ "$tpm_absent" = "0" ]; then
        ! cryptfs-tpm2 -q unseal passphrase -P auto -o "$tmp_dir/passphrase" &&
            print_error "Unable to unseal the passphrase" && return 1

        passphrase="$tmp_dir/passphrase"
    fi

    ! cryptsetup --type luks --cipher aes-xts-plain --hash sha256 \
        --use-random --key-file "$passphrase" luksFormat "$luks_dev" &&
        print_error "Unable to create the LUKS partition on $luks_dev" &&
        return 1

    return 0
}

function map_luks_partition()
{
    local luks_dev="$1"
    local luks_name="$2"
    local tpm_absent="$3"
    local tmp_dir="$4"
    local passphrase="-"

    print_info "Mapping the LUKS partition $luks_name ..."

    [ "$tpm_absent" = "0" ] && passphrase="$4/passphrase"

    ! cryptsetup luksOpen --key-file "$passphrase" "$luks_dev" "$luks_name" &&
        print_error "Unable to map the LUKS partition $luks_name" && return 1

    return 0
}

function unmap_luks_partition()
{
    local luks_name="$1"

    [ -e "/dev/mapper/$luks_name" ] && print_info "Unmapping the LUKS partition $luks_name ..." &&
        cryptsetup luksClose "$luks_name"
}

function option_check()
{
    if [ -z "$1" ] || echo "$1" | grep -q "^-"; then
        print_error "No value specified for option $arg"
        exit 1
    fi
}

function show_help()
{
    cat <<EOF
$PROG_NAME - creation tool for LUKS partition
Version: $VERSION

(C)Copyright 2016-2017, Lans Zhang <jia.zhang@windriver.com>, Wind River Systems, Inc.

Usage: $1 options...

Options:
 -d|--dev <device>
     Set the path to the device node where the LUKS partition is manipulated.
     e.g, /dev/sda1

 -N|--no-setup
     In no setup mode you can map/unmap existing LUKS partitions.

 -n|--name <mapped name>
    (Optional) Set the mapped name for the dmcrypt target device.
    e.g. /dev/mapper/<mapped name>.

    The default name is $DEFAULT_ENCRYPTION_NAME.

 -f|--force
    (Optional) Enforce creating the LUKS partition if already existed.

 -m|--map-existing
    (Optional) Map previously created LUKS partition.

 -u|--unmap
    (Optional) Unmap the created LUKS partition before exiting.

 -t|--no-tpm
    (Optional) Don't use TPM.

    By default, TPM is probed automatically.

 -e|--evict-all
    (Optional) Always evict the primary key and passphrase.

 -V|--verbose
    (Optional) Show the verbose output.

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
OPT_EVICT_ALL=0
OPT_VERBOSE=0
OPT_MAP_EXISTING_LUKS=0
OPT_NO_SETUP=0

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
	-e|--evict-all)
	    OPT_EVICT_ALL=1
	    ;;
	-V|--verbose)
	    OPT_VERBOSE=1
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

trap "trap_handler $?" SIGINT EXIT

OPT_LUKS_NAME="${OPT_LUKS_NAME:-$DEFAULT_ENCRYPTION_NAME}"

###### OPT_NO_SETUP Handling start ######
if [ $OPT_NO_SETUP -eq 1 ] && [ $OPT_UNMAP_LUKS -eq 1 ] ; then
    unmap_luks_partition "$OPT_LUKS_NAME"
    exit 0
fi

[ x"$OPT_LUKS_DEV" = x"" ] && print_error "LUKS device is not specified" &&
    exit 1

TEMP_DIR=`mktemp -d /tmp/luks-setup.XXXXXX`
print_verbose "Temporary directory created: $TEMP_DIR"
[ ! -d "$TEMP_DIR" ] && print_error "Failed to create the temporary directory" &&
    exit 1

if [ $OPT_NO_SETUP -eq 1 ] ; then
    if [ $OPT_MAP_EXISTING_LUKS -eq 1 ]; then
	if ! is_luks_partition "$OPT_LUKS_DEV"; then
            print_info "$OPT_LUKS_DEV is not a LUKS partition"
            exit 1
	fi

	! unseal_passphrase "$TEMP_DIR/passphrase" && exit 1

	if [ $OPT_NO_TPM -eq 0 ] ; then
	    detect_tpm
	    [ $? -eq 0 ] && TPM_ABSENT=0
	fi

	! map_luks_partition "$OPT_LUKS_DEV" "$OPT_LUKS_NAME" \
            "$TPM_ABSENT" "$TEMP_DIR" && exit 1

	print_info "The LUKS partition $OPT_LUKS_NAME is created on $OPT_LUKS_DEV"
    fi
    exit 0
fi

###### OPT_NO_SETUP Handling end ######
if is_luks_partition "$OPT_LUKS_DEV"; then
    print_info "$OPT_LUKS_DEV is already a LUKS partition"
    [ $OPT_FORCE_CREATION -eq 0 ] && exit 0

    print_info "Enforce creating the LUKS partition"
fi

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

if [ $OPT_NO_TPM -eq 0 ]; then
    detect_tpm
    if [ $? -eq 0 ]; then
        if [ $OPT_EVICT_ALL -eq 1 ]; then
            tpm2_takeownership -c

            # Ignore the error messages if something gets wrong
            cryptfs-tpm2 -q evict all 2>/dev/null

            ! cryptfs-tpm2 -q seal all -P auto &&
                print_error "Unable to create the primary key and passphrase" &&
                exit 1
        fi

        TPM_ABSENT=0
    fi
fi

if [ $TPM_ABSENT = 1 ]; then
    echo
    print_critical "**************************************************"
    print_critical "The plain passphrase cannot be protected by a TPM."
    print_critical "You have to type the passphrase when prompted."
    print_critical "Take the risk by self if leaked by accident."
    print_critical "**************************************************"
    echo
fi

! create_luks_partition "$OPT_LUKS_DEV" \
    "$OPT_LUKS_NAME" "$TPM_ABSENT" "$TEMP_DIR" && exit 1

! map_luks_partition "$OPT_LUKS_DEV" "$OPT_LUKS_NAME" \
    "$TPM_ABSENT" "$TEMP_DIR" && exit 1

[ $OPT_UNMAP_LUKS -eq 1 ] && unmap_luks_partition "$OPT_LUKS_NAME"

print_info "The LUKS partition $OPT_LUKS_NAME is created on $OPT_LUKS_DEV"
