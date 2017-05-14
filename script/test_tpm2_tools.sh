#!/bin/sh

# Cryptfs-TPM2 testing script with tpm2.0-tools
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
#        Lans Zhang <jia.zhang@windriver.com>
#

PRI_KEY_SECRET="H31i05"
PASS_SECRET="h31i05"
PRI_KEY_HANDLE=0x817FFFFF
PASS_HANDLE=0x817FFFFE

tmpdir=`mktemp -d /tmp/cryptfs-tpm2.XXXXXX`
PRI_KEY_CONTEXT_BLOB="$tmpdir/pri_key_context_blob"
PASS_PUB_BLOB="$tmpdir/passphrase_pub_blob"
PASS_PRIV_BLOB="$tmpdir/passphrase_priv_blob"
PASS_CONTEXT_BLOB="$tmpdir/passphrase_context_blob"
PASS_NAME_BLOB="$tmpdir/passphrase_name_blob"
PASS_BLOB="$tmpdir/passphrase_blob"
PASS="$tmpdir/passphrase"

# Assume TPM is clear
function check_ownership()
{
	tpm2_takeownership -c
	[ $? != 0 ] && echo "TPM is not clear" && exit 1
}

# Create a primary key in owner hierarchy
function create_primary_key()
{
	# SHA256 algorithm used for computing the name of the primary key
	local hash_alg=0xb
	# RSA algorithm associated with the primary key
	local key_alg=0x1

	echo "Creating a primary key ..."
	tpm2_createprimary --auth o --halg $hash_alg --kalg $key_alg \
		--pwdk "$PRI_KEY_SECRET" --context "$PRI_KEY_CONTEXT_BLOB"
	[ $? != 0 ] && echo "Unable to create the primary key" && exit 2

	# Make the primary key persistent in the TPM, otherwise it will be need
	# to be recreated after each TPM Reset if not context saved, or reloaded
	# with the saved context.
	echo "Making the primary key persistent ..."
	tpm2_evictcontrol --auth o --context "$PRI_KEY_CONTEXT_BLOB" \
		--persistent $PRI_KEY_HANDLE
	[ $? != 0 ] && echo "Unable to make the primary key persistent" && exit 3

	rm -f "$PRI_KEY_CONTEXT_BLOB"
}

# Create the passphase used to decrypt LUKS master key
function create_passphrase()
{
	# SHA256 algorithm used for computing the name of the sealed passphase
	local hash_alg=0xb
	# Keyedhash algorithm associated with the sealed passphase
	local key_alg=0x8

	echo "Generating a passphrase ..."
	tpm2_getrandom --size 32 --of "$PASS"
	[ $? != 0 ] && echo "Unable to generate the passphrase" && exit 4

	echo "Sealing the passphrase ..."
	tpm2_create --halg $hash_alg --kalg $key_alg --parent "$PRI_KEY_HANDLE" \
		--inFile "$PASS" --pwdp "$PRI_KEY_SECRET" --pwdk "$PASS_SECRET" \
		--opu "$PASS_PUB_BLOB" --opr "$PASS_PRIV_BLOB"
	[ $? != 0 ] && echo "Unable to create the sealed passphrase" && exit 5

	echo "Loading the passphrase ..."
	tpm2_load --parent "$PRI_KEY_HANDLE" --pwdp "$PRI_KEY_SECRET" --pubfile "$PASS_PUB_BLOB" \
		--privfile "$PASS_PRIV_BLOB" --context "$PASS_CONTEXT_BLOB" \
		--name "$PASS_NAME_BLOB"
	[ $? != 0 ] && echo "Unable to load the passphrase" && exit 6

	rm -f "$PASS_NAME_BLOB"
	rm -f "$PASS_PUB_BLOB"
	rm -f "$PASS_PRIV_BLOB"

	# Make the passphrase persistent in the TPM
	echo "Making the passphrase persistent ..."
	tpm2_evictcontrol --auth o --context "$PASS_CONTEXT_BLOB" \
		--persistent $PASS_HANDLE
	[ $? != 0 ] && echo "Unable to make the passphrase persistent" && exit 7

	rm -f "$PASS_CONTEXT_BLOB"
}

function show_passphrase()
{
	echo "Showing the passphrase ..."
	hexdump -C "$PASS"
	rm -f "$PASS"

	echo "Unsealing the passphrase ..."
	tpm2_unseal --item "$PASS_HANDLE" --pwdi "$PASS_SECRET" --outfile "$PASS_BLOB"
	[ $? != 0 ] && echo "Unable to unseal the passphrase" && exit 8
}

function evict_all()
{
	echo "Evicting the passphrase ..."
	tpm2_evictcontrol --auth o --handle $PRI_KEY_HANDLE --persistent $PRI_KEY_HANDLE
	[ $? != 0 ] && echo "Unable to evict the passphrase" && exit 9

	echo "Evicting the primary key ..."
	tpm2_evictcontrol --auth o --handle $PASS_HANDLE --persistent $PASS_HANDLE
	[ $? != 0 ] && echo "Unable to evict the primary key" && exit 10
}

check_ownership
create_primary_key
create_passphrase
show_passphrase
evict_all

echo "[*] cryptfs-tpm2 testing complete!"
exit 0
