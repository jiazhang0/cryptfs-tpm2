#!/bin/bash

tpm2_flushcontext --transient-object
tpm2_evictcontrol -C o -c 0x817FFFFF
tpm2_evictcontrol -C o -c 0x817FFFFE
