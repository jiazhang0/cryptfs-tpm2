#!/bin/sh

# Cryptfs-TPM2 testing script
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

function check_ownership()
{
	tpm2_takeownership -c
	[ $? != 0 ] && echo "TPM is not clear" && exit 1
}

function seal_all()
{
	local opts=""

	if [ -n "$1" ]; then
		case $1 in
		sha1|sha256|auto)
        		;;
		*)
			echo "Unsupported PCR bak option for seal sub-command"
			exit 1
			;;
		esac

		opts=" -P $1"
	fi

	cryptfs-tpm2 -q seal all $opts
}

function unseal_passphrase()
{
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

log=`mktemp cryptfs-tpm2-test-XXXX`

echo -n "[*] testing object generation without PCR ... "
test_all >$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"

echo -n "[*] testing object generation with SHA1 PCR bank ... "
test_all sha1 >>$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"

echo -n "[*] testing object generation with SHA256 PCR bank ... "
test_all sha256 >>$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"

echo -n "[*] testing object generation with auto PCR bank ... "
test_all auto >>$log 2>&1 && echo "[SUCCEEDED]" || echo "[FAILED]"
