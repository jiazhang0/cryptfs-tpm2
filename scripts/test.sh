#!/bin/sh

# Cryptfs-TPM2 testing script
#
# Copyright (c) 2016-2017, Wind River Systems, Inc.
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
#        Jia Zhang <qianyue.zj@alibaba-inc.com>
#

function check_ownership()
{
	tpm2_takeownership -c
	[ $? != 0 ] && echo "TPM is not clear" && exit 1
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

evict_all >/dev/null 2>&1

log=`mktemp /tmp/cryptfs-tpm2-test-log-XXXX`
echo "The testing log is placed at $log"

echo -n "[*] testing object generation without PCR ... "
test_all >$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"

echo -n "[*] testing object generation with SHA1 PCR bank ... "
test_all sha1 >>$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"

echo -n "[*] testing object generation with SHA256 PCR bank ... "
test_all sha256 >>$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"

echo -n "[*] testing object generation with auto PCR bank ... "
test_all auto >>$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"

echo -n "[*] testing DA recovery ... "
tpm2_takeownership --clear >>$log 2>&1
tpm2_takeownership --ownerPasswd owner --lockPasswd lockout >>$log 2>&1
tpm2_dictionarylockout --lockout-passwd lockout --clear-lockout >>$log 2>&1
tpm2_dictionarylockout --lockout-passwd lockout --setup-parameters \
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

tpm2_takeownership --clear --oldLockPasswd lockout >>$log 2>&1
