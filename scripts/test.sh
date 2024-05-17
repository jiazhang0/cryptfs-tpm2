#!/bin/sh

# Cryptfs-TPM2 testing script
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

PCRS=()

function check_ownership()
{
	tpm2_changeauth --object-context=owner
	[ $? != 0 ] && echo "TPM is not clear" && exit 1
}

function detect_pcrs()
{
	local res="`tpm2_getcap pcrs`"
	local pcrs=': \[ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 \]'

	if echo "$res" | grep -q "sha1$pcrs"; then
		PCRS+=("sha1")
		echo "TPM supports SHA1"
	fi

	if echo "$res" | grep -q "sha256$pcrs"; then
		PCRS+=("sha256")
		echo "TPM supports SHA256"
	fi
}

function seal_all()
{
	echo "Sealing all ..."

	local opts="$EXTRA_SEAL_OPTS"

	if [ -n "$1" ]; then
		case $1 in
		sha1|sha256|auto)
        		;;
		*)
			echo "Unsupported PCR bak option for seal sub-command"
			exit 1
			;;
		esac

		opts="$opts -P $1"
	fi

	cryptfs-tpm2 -q seal all $opts
}

function unseal_passphrase()
{
	echo "Unsealing passphrase ..."

	local opts=""

	if [ -n "$1" ]; then
		case $1 in
		sha1|sha256|auto)
        		;;
		*)
			echo "Unsupported PCR bank option for unseal sub-command"
			exit 1
			;;
		esac

		opts=" -P $1"
	fi

	cryptfs-tpm2 -q unseal passphrase $opts
}

function evict_all()
{
	echo "Evicting all ..."

	cryptfs-tpm2 -q evict all
}

function test_all()
{
	seal_all $1 || return 1
	unseal_passphrase $1 || return 1
	evict_all || return 1
}

check_ownership

detect_pcrs

evict_all >/dev/null 2>&1

tpm2_flushcontext --transient-object

log=`mktemp /tmp/cryptfs-tpm2-test-log-XXXX`
echo "The testing log is placed at $log"

echo -n "[*] testing object generation without PCR ... "
test_all >$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"

if printf '%s\n' "${PCRs[@]}" | grep -wq "sha1"; then
    echo -n "[*] testing object generation with SHA1 PCR bank ... "
    test_all sha1 >>$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"
fi

if printf '%s\n' "${PCRs[@]}" | grep -wq "sha256"; then
    echo -n "[*] testing object generation with SHA256 PCR bank ... "
    test_all sha256 >>$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"
fi

echo -n "[*] testing object generation with auto PCR bank ... "
test_all auto >>$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"

echo -n "[*] testing DA recovery ... "
tpm2_changeauth --object-context=owner >>$log 2>&1
tpm2_changeauth --object-context=lockout >>$log 2>&1
tpm2_changeauth --object-context=owner owner >>$log 2>&1
tpm2_changeauth --object-context=lockout lockout >>$log 2>&1
tpm2_dictionarylockout --auth=lockout --clear-lockout >>$log 2>&1
tpm2_dictionarylockout --auth=lockout --setup-parameters \
    --max-tries 1 \
    --recovery-time 30 \
    --lockout-recovery-time 60 >>$log 2>&1

echo "Sealing all with secret set ..." >>$log 2>&1
cryptfs-tpm2 -q --owner-auth owner --key-secret key --passphrase-secret pass \
    seal all -P auto >>$log 2>&1
[ $? -ne 0 ] && echo "[FAILED]" || {
    echo "Unsealing passphrase with wrong secret ..." >>$log 2>&1
    cryptfs-tpm2 -q --passphrase-secret pass1 \
        unseal passphrase -P auto 2>&1 | grep -q 0x98e

    [ $? -ne 0 ] && echo "[FAILED]" || {
        cryptfs-tpm2 -q --passphrase-secret pass1 \
            unseal passphrase -P auto 2>&1 | grep -q 0x921

        [ $? -ne 0 ] && echo "[FAILED]" || {
            tpm2_dictionarylockout --auth=lockout --clear-lockout >>$log 2>&1

            echo "Unseal passphrase and reset DA lockout ..." >>$log 2>&1
            cryptfs-tpm2 -q --lockout-auth lockout \
                --passphrase-secret pass \
                unseal passphrase -P auto >>$log 2>&1

            [ $? -ne 0 ] && echo "[FAILED]" || {
                cryptfs-tpm2 -q --owner-auth owner evict all >>$log 2>&1
                [ $? -eq 0 ] && echo "[SUCCEEDED]" || echo "[FAILED]"
            }
        }
    }
}

echo -n "[*] testing object generation without DA ... "
echo "Sealing all with secret set ..." >>$log 2>&1
cryptfs-tpm2 -q --owner-auth owner --key-secret key --passphrase-secret pass \
    seal all -P auto --no-da >>$log 2>&1
[ $? -ne 0 ] && echo "[FAILED]" || {
    echo "Unsealing passphrase with wrong secret ..." >>$log 2>&1
    cryptfs-tpm2 -q --passphrase-secret pass1 \
        unseal passphrase -P auto 2>&1 | grep -q 0x9a2

    [ $? -ne 0 ] && echo "[FAILED]" || {
        cryptfs-tpm2 -q --passphrase-secret pass1 \
            unseal passphrase -P auto 2>&1 | grep -q 0x9a2

        [ $? -ne 0 ] && echo "[FAILED]" || {
            echo "Unseal passphrase ..." >>$log 2>&1
            cryptfs-tpm2 -q --passphrase-secret pass \
                unseal passphrase -P auto >>$log 2>&1

            [ $? -ne 0 ] && echo "[FAILED]" || {
                cryptfs-tpm2 -q --owner-auth owner evict all >>$log 2>&1
                [ $? -eq 0 ] && echo "[SUCCEEDED]" || echo "[FAILED]"
            }
        }
    }
}

# For cleanup
cryptfs-tpm2 -q --owner-auth owner --key-secret key --passphrase-secret pass \
    evict all >/dev/null 2>&1
tpm2_changeauth --object-context=lockout --object-auth=lockout >/dev/null 2>&1
tpm2_changeauth --object-context=owner --object-auth=owner >/dev/null 2>&1
