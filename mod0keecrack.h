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
 * Description: Project header file. Datatypes und function prototypes.
 */

#ifndef _MOD0KEECRACK_H
#define _MOD0KEECRACK_H

typedef uintmax_t	off_t;


enum _m0_kdbx_headerid {
	END,
	COMMENT,
	CIPHERID,
	COMPRESSIONFLAGS,
	MASTERSEED,
	TRANSFORMSEED,				// 5
	TRANSFORMROUNDS,
	ENCRYPTIONIV,
	PROTECTEDSTREAMKEY,
	STREAMSTARTBYTES,
	INNERRANDOMSTREAMID, 	// 10
	HEADERIDCOUNT
};

typedef enum _m0_kdbx_headerid m0_kdbx_headerid_t;

typedef struct _m0_kdbx_header_entry {
	uint8_t 	id;
	uint16_t 	len;
	uint8_t 	*data;
	uint32_t	dw;
	uint64_t	qw;
} m0_kdbx_header_entry_t;
	
	
typedef struct _m0_kdbx_header {
	uint32_t magic;
	uint32_t identifier;
	uint16_t minor_version;
	uint16_t major_version;
} m0_kdbx_header_t;

typedef struct _m0_kdbx_payload {
	off_t	offset_start;
	off_t pos;
	size_t len;
	uint8_t	*encrypted;
	uint8_t	*decrypted;	

} m0_kdbx_payload_t;

typedef struct _m0kdbx_data {
		m0_kdbx_header_t	header;
    size_t 		data_len;
    uint8_t 	*data;
} m0_kbdx_data_t;

typedef struct _m0_kdbx_database {
  m0_kdbx_header_t        fileheader;
  m0_kdbx_header_entry_t  kdbxheader;
  m0_kdbx_payload_t       payload;
} m0_kdbx_database_t;

// Function prototypes

size_t  kdbx_headerentries_free(m0_kdbx_header_entry_t *);
size_t  kdbx_headerentries_read(FILE *, m0_kdbx_header_entry_t *);
void    kdbx_headerentries_dump(m0_kdbx_header_entry_t *);

size_t  kdbx_header_read(FILE *, m0_kdbx_header_t *);
void    kdbx_header_dump(m0_kdbx_header_t);

size_t  kdbx_payload_read(FILE *, m0_kdbx_payload_t *);
void    kdbx_payload_dump(m0_kdbx_payload_t);
bool    kdbx_payload_crack(m0_kdbx_database_t *, FILE *);

bool    kdbx_decrypt_payload(m0_kdbx_database_t *, char *, uint8_t *);

#endif
