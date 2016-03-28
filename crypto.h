/*
 * Copyright (c) 2016, mod0keecrack
 *    Thorsten Schroeder <ths at modzero dot ch>
 *
 * All rights reserved.
 *
 * This file is part of mod0keecrack.
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Thorsten Schroeder <ths at modzero dot ch> wrote this file. As long as you 
 * retain this notice you can do whatever you want with this stuff. If we meet 
 * some day, and you think this stuff is worth it, you can buy me a beer in 
 * return. Thorsten Schroeder.
 *
 * NON-MILITARY-USAGE CLAUSE
 * Redistribution and use in source and binary form for military use and 
 * military research is not permitted. Infringement of these clauses may
 * result in publishing the source code of the utilizing applications and 
 * libraries to the public. As this software is developed, tested and
 * reviewed by *international* volunteers, this clause shall not be refused 
 * due to the matter of *national* security concerns.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE DDK PROJECT BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * File: mod0keecrack.h
 * Description: Project header files.
 */
 
#ifndef _CRYPTO_H
#define _CRYPTO_H

// implementation in platform specific files: crypto-XX.c
int aes_transformkey(m0_kdbx_header_entry_t *hdr, uint8_t *tkey, size_t tkeylen);
int aes_decrypt_check(m0_kdbx_header_entry_t *hdr, uint8_t *masterkey, m0_kdbx_payload_t *p);
int sha256_hash(uint8_t *hash, uint8_t *data, size_t len);

#endif
