#!/bin/bash

luks-setup --unmap
rpm -e cryptsetup
clear

run() {
    local cmd="$1"
    echo "# $cmd"
    eval "$cmd"
}

run "luks-setup --dev /dev/nvme2n1p1 --force"
run "lsblk"
run "luks-setup --unmap"
run "lsblk"

run "luks-setup --dev /dev/nvme2n1p1 --force --no-tpm"
run "lsblk"
run "luks-setup --unmap"
run "lsblk"
