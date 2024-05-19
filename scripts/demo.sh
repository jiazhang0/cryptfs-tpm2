#!/bin/bash

LUKS_DEVICE="${LUKS_DEVICE:-/dev/nvme2n1p1}"

luks-setup --dev "$LUKS_DEVICE" --unmap
rpm -e cryptsetup
clear

trap_handler() {
    trap - SIGINT ERR

    local line_no="$1"
    local err=$2

    if [ $err -ne 0 ] && [ "$line_no" != "1" ]; then
        echo "Error occurred on line $line_no, exit code: $err"
    fi

    exit $err
}

trap 'trap_handler $LINENO $?' SIGINT ERR

run() {
    local cmd="$1"

    echo -e "\033[1;31m[?] ============\033[0m"
    echo -e "\033[1;32m# $cmd\033[0m"
    eval "$cmd"
    echo -e "\033[1;31m[!] ============\033[0m"
}

if [ -e "/dev/tpm0" ]; then
    run "luks-setup --dev $LUKS_DEVICE --force --verbose"
    run "cryptsetup luksDump $LUKS_DEVICE"
    run "lsblk"

    run "luks-setup --dev $LUKS_DEVICE --unmap --verbose"
    run "lsblk"

    run "luks-setup --dev $LUKS_DEVICE --recovery --verbose"
fi

run "luks-setup --dev $LUKS_DEVICE --force --unmap --no-tpm --verbose"
run "cryptsetup luksDump $LUKS_DEVICE"
run "lsblk"

run "luks-setup --dev $LUKS_DEVICE --no-tpm --recovery --verbose"
