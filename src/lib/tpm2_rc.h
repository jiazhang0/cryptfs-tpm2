/*
 * Copyright (c) 2016-2017, Wind River Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3) Neither the name of Wind River Systems nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Author:
 *        Jia Zhang <zhang.jia@linux.alibaba.com>
 */

#ifndef __TPM2_RC_H__
#define __TPM2_RC_H__

#include <cryptfs_tpm2.h>

/* To understand the TPM2_RC you need to read a 2 different parts of the
 * spec:
 * Section 39.4 of TPM 2.0 Part 1: Architecture
 * Section 6.6  of TPM 2.0 Part 2: Structures
 *
 * The notion of RC levels only exists for the TSS. See the TSS system API
 * specification section 6.1.2 for details.
 */

/* Macros to determine whether or not a specific bit in position 'pos' from
 * variable 'var' is set.
 */
#define IS_BIT_SET(var, pos) ((1 << (pos)) & (var))
#define IS_BIT_CLEAR(var, pos) !IS_BIT_SET(var, pos)

/* useful masks not defined in the spec */
/* bits [06:00] */
#define TPM2_RC_7BIT_ERROR_MASK      0x7f
/* bits [05:00] */
#define TPM2_RC_6BIT_ERROR_MASK      0x3f
/* bits [11:08] */
#define TPM2_RC_PARAMETER_MASK       0xf00
/* bits [10:08] */
#define TPM2_RC_HANDLE_MASK          0x700
#define TPM2_RC_SESSION_MASK         0x700

/* "Format Zero" response codes have bit 7 clear.
 * Format zero RCs could be in a number of formats:
 * - A TPM 1.2 RC
 * - A vendor defined error code
 * - A 6 bit warning code
 * - A 6 bit error code
 */
static inline bool
tpm2_rc_is_format_zero (TPM2_RC response_code)
{
    if (IS_BIT_CLEAR (response_code, 7))
        return true;
    else
        return false;
}
/* "Format One" response codes have bit 7 set.
 * These RCs have two components:
 * - A 5 bit error code in bits [05:00]
 * - A 4 bit parameter identifier in [11:08] or a 3 bit handle / session
 *   identifier in bits [10:08]
 */
static inline int
tpm2_rc_is_format_one (TPM2_RC response_code)
{
    if (IS_BIT_SET (response_code, 7))
        return true;
    else
        return false;
}
/* Determine whether or not a response code (TPM2_RC) is in the 1.2 format or
 * the 2.0 format.
 */
static inline bool
tpm2_rc_is_tpm2 (TPM2_RC response_code)
{
    /* if bit 7 & 8 are both 0, TPM2_RC is 1.2 format */
    if (IS_BIT_CLEAR (response_code, 7) && IS_BIT_CLEAR (response_code, 8))
        return false;
    else
        return true;
}
static inline bool
tpm2_rc_is_tpm12 (TPM2_RC response_code)
{
    if (!tpm2_rc_is_tpm2 (response_code))
        return true;
    else
        return false;
}
/* Determine whether or not a response code (TPM2_RC) is a vendor defined code.
 * Vendor defined TPM2 response codes have bit 8 and 10 set, and bit 7 clear.
 */
static inline bool
tpm2_rc_is_vendor_defined (TPM2_RC response_code)
{
    if (IS_BIT_CLEAR (response_code,  7) &&
        IS_BIT_SET   (response_code,  8) &&
        IS_BIT_SET   (response_code, 10))
    {
        return true;
    } else {
        return false;
    }
}
/* Determine whether or not bits [06:00] contain a warning code.
 * Warning codes have bit 8 and 11 set, and bits 7 and 10 clear.
 */
static inline bool
tpm2_rc_is_warning_code (TPM2_RC response_code)
{
    if (IS_BIT_CLEAR (response_code,  7) &&
        IS_BIT_SET   (response_code,  8) &&
        IS_BIT_CLEAR (response_code, 10) &&
        IS_BIT_SET   (response_code, 11))
    {
        return true;
    } else {
        return false;
    }
}
/* Determine whether or not bits [06:00] contain an error code.
 * Error codes have bit 8 set, and bits 7, 10 and 11 clear.
 */
static inline bool
tpm2_rc_is_error_code (TPM2_RC response_code)
{
    if (IS_BIT_CLEAR (response_code,  7) &&
        IS_BIT_SET   (response_code,  8) &&
        IS_BIT_CLEAR (response_code, 10) &&
        IS_BIT_CLEAR (response_code, 11))
    {
        return 1;
    } else {
        return 0;
    }
}
/* Determine whether or not bits [05:00] contain and error code with a
 * parameter number in bits [11:08].
 * Bit 6 and 7 are set.
 */
static inline bool
tpm2_rc_is_error_code_with_parameter (TPM2_RC response_code)
{
    if (IS_BIT_SET (response_code, 6) && IS_BIT_SET (response_code, 7))
        return true;
    else
        return false;
}
/* Determine whether or not bits [05:00] contain an error code with a
 * handle number in bits [10:08]
 * Bit 7 set, bits 6 and 11 clear.
 */
static inline bool
tpm2_rc_is_error_code_with_handle (TPM2_RC response_code)
{
    if (IS_BIT_CLEAR (response_code,  6) &&
        IS_BIT_SET   (response_code,  7) &&
        IS_BIT_CLEAR (response_code, 11))
    {
        return true;
    } else {
        return false;
    }
}
/* Determine whether or not bits [05:00] contain an error code with a
 * session number in bits [10:08]
 * Bit 6 clear, bits 7 and 11 set.
 */
static inline bool
tpm2_rc_is_error_code_with_session (TPM2_RC response_code)
{
    if (IS_BIT_CLEAR (response_code,  6) &&
        IS_BIT_SET   (response_code,  7) &&
        IS_BIT_SET   (response_code, 11))
    {
        return true;
    } else {
        return false;
    }
}
/* Isolate bits [06:00] of the TPM2_RC.
 * The 7bit warning or error code is only valid if the RC is a "format zero"
 * RC.
 */
static inline UINT32
tpm2_rc_get_code_7bit (TPM2_RC response_code)
{
    return TPM2_RC_7BIT_ERROR_MASK & response_code;
}
/* Isolate bits [05:00] of the TPM2_RC.
 * The 6bit error code is only valid if the RC is a "format one" RC.
 */
static inline UINT32
tpm2_rc_get_code_6bit (TPM2_RC response_code)
{
    return TPM2_RC_6BIT_ERROR_MASK & response_code;
}
/* Isolate bits [11:08] of the TPM2_RC.
 * The 4 it parameter code is only valid if the RC is a "format one" RC
 * with bit 6 set. Test for this with the
 * tpm2_rc_is_error_code_with_parameters function.
 */
static inline UINT32
tpm2_rc_get_parameter_number (TPM2_RC response_code)
{
    return TPM2_RC_PARAMETER_MASK & response_code;
}
/* Isolate bits [10:08] of the TPM2_RC.
 * The 3 bit handle / session code is only valid if the RC is a "format one"
 * RC with bits 6 clear.
 */
static inline UINT32
tpm2_rc_get_handle_number (TPM2_RC response_code)
{
    return TPM2_RC_HANDLE_MASK & response_code;
}
static inline UINT32
tpm2_rc_get_session_number (TPM2_RC response_code)
{
    return TPM2_RC_SESSION_MASK & response_code;
}
/* Isolate the error level component of the TPM2_RC in bits [23:16] */
static inline UINT32
tpm2_rc_get_layer (TPM2_RC response_code)
{
    return TSS2_RC_LAYER_MASK & response_code;
}
/* This function returns true if the error code indicates that it came from a
 * TSS component. False otherwise (which indicates it came from the TPM).
 */
static inline bool
tpm2_rc_is_from_tss (TPM2_RC response_code)
{
    if (tpm2_rc_get_layer (response_code))
        return true;
    else
        return false;
}
/* Isolate the error code from a TSS layer. It's not entirely clear to me
 * from the spec what the right mask is here. Bits [23:16] are for the layer
 * indicator but it says nothing else about which bits mean what. It makes
 * sense to assume that the lower 2 bytes hold the error code but the top
 * byte (AFAIK) is unaccounted for.
 * So I'm masking [31:24] as well as the ayer indicator.
 */
static inline UINT32
tpm2_rc_get_tss_err_code (TPM2_RC response_code)
{
    return 0X0000ffff & response_code;
}

#endif  /* __TPM2_RC_H__ */
