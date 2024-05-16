#!/bin/bash

tpm2_getcap properties-variable | grep LOCKOUT
tpm2_getcap properties-variable | grep TPM2_PT_MAX_AUTH_FAIL
tpm2_getcap properties-variable | grep inLockout
