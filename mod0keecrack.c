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
 * File: mod0keecrack.c
 * Description: Implementation of a KeepassX 2 database password cracker.
 */



#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "helper.h"
#include "mod0keecrack.h"
#include "crypto.h"

static void usage(char *prog);
static char *kdbx_filename;

size_t kdbx_headerentries_free(m0_kdbx_header_entry_t *e)
{
  size_t i = 0;

  for(i=0; i<HEADERIDCOUNT;i++) {

    if(e[i].data != NULL) {
      free(e[i].data);
      memset(&e[i], 0, sizeof(m0_kdbx_header_entry_t));
    }
  }
  return i;
}

size_t kdbx_headerentries_read(FILE *kdbx_fd, m0_kdbx_header_entry_t *entries)
{
  size_t ret = 0;
  size_t result = 0;

  uint8_t id = 0;

  if (entries == NULL)
    return 0;

  do {

    // headers have variable lengths.
    // we need to read: [1 byte hdr-id] [1 word data-len] [data-len bytes of value]
    // if hdr-id == 0x00: header ends, encrypted payload starts.

    ret = fread(&id, sizeof(uint8_t), 1, kdbx_fd);

    if ( ret != 1)
      printf("[!] fread(id) failed.");

    if(id > HEADERIDCOUNT) {
      id = END;
      continue;
    }

    entries[id].id = id;

    ret = fread(&entries[id].len, sizeof(uint16_t), 1, kdbx_fd);

    if ( ret != 1)
      printf("[!] fread(hdrlen) failed.");

    entries[id].data = (uint8_t *)malloc(entries[id].len);

    if(entries[id].data == NULL) {
      printf("[!] malloc(entries[id].len) failed.");
      break;
    }

    ret = fread(entries[id].data, entries[id].len, 1, kdbx_fd);

    if ( ret != 1)
      printf("[!] fread(entries[%d].data) failed.", id);

    if( (id == 3) || (id==10) ) {
      memcpy(&entries[id].dw, entries[id].data, 4);
      memcpy(&entries[id].qw, entries[id].data, 4);
    } else if( id == 6 ) {
      memcpy(&entries[id].qw, entries[id].data, 8);
    }
    result++;

  } while (id != END);

  return result;
}

void kdbx_headerentries_dump(m0_kdbx_header_entry_t *h)
{
  printf("[*] kdbx headerentries:\n");
  printf("[-]    END:                 "); print_hex_buf(h[0].data, h[0].len); puts("");
  printf("[-]    COMMENT:             "); print_hex_buf(h[1].data, h[1].len); puts("");
  printf("[-]    CIPHERID:            "); print_hex_buf(h[2].data, h[2].len); puts("");
  printf("[-]    COMPRESSIONFLAGS:    %08x\n", h[3].dw );
  printf("[-]    MASTERSEED:          "); print_hex_buf(h[4].data, h[4].len); puts("");
  printf("[-]    TRANSFORMSEED:       "); print_hex_buf(h[5].data, h[5].len); puts("");
  printf("[-]    TRANSFORMROUNDS:     %016llx\n", h[6].qw );
  printf("[-]    ENCRYPTIONIV:        "); print_hex_buf(h[7].data, h[7].len); puts("");
  printf("[-]    PROTECTEDSTREAMKEY:  "); print_hex_buf(h[8].data, h[8].len); puts("");
  printf("[-]    STREAMSTARTBYTES:    "); print_hex_buf(h[9].data, h[9].len); puts("");
  printf("[-]    INNERRANDOMSTREAMID: %08x\n", h[10].dw );
  return;
}

size_t kdbx_header_read(FILE *kdbx_fd, m0_kdbx_header_t *header)
{
  size_t ret = 0;

  if (header == NULL)
    return 0;

  ret = fread(header, sizeof(m0_kdbx_header_t), 1, kdbx_fd);
  if ( ret != 1)
    printf("[!] fread(m0_kdbx_header) failed.");

  return ret;
}

void kdbx_header_dump(m0_kdbx_header_t h)
{
  printf("[*] kdbx header:\n");
  printf("[-]    file magic:          %08x\n", h.magic);
  printf("[-]    file identifier:     %08x\n", h.identifier);
  printf("[-]    file minor version:  %04x\n", (h.minor_version));
  printf("[-]    file major version:  %04x\n", (h.major_version));
  return;
}

size_t kdbx_payload_read(FILE *kdbx_fd, m0_kdbx_payload_t *p)
{
  size_t         ret = 0;
  size_t payload_len = 0;
  off_t    off_start = 0;
  off_t      off_end = 0;

  if (p == NULL)
    return 0;

  off_start = ftell(kdbx_fd);

  fseek(kdbx_fd, 0, SEEK_END);
  off_end = ftell(kdbx_fd);
  fseek(kdbx_fd, off_start, SEEK_SET);

  p->offset_start = off_start;
  p->len          = (off_end-off_start);
  p->encrypted    = (uint8_t *)malloc(p->len);

  if(p->encrypted == NULL) {
    printf("[!] malloc(payload->encrypted) failed.");
    return 0;
  }

  memset(p->encrypted, 0, p->len);

  ret = fread(p->encrypted, p->len, 1, kdbx_fd);
  if ( ret != 1)
    printf("[!] fread(payload) failed.");

  return ret;
}

void kdbx_payload_dump(m0_kdbx_payload_t p)
{
  printf("[*] kdbx payload:\n");
  printf("[-]    payload offset:      %llx\n", p.offset_start);
  printf("[-]    payload len:         %x\n", p.len);

  return;
}

bool kdbx_payload_crack(m0_kdbx_database_t *db, FILE *wordlist_fd)
{
  bool res = false;
  char pass[1024] = {0};
  FILE *keyfd = NULL;
  uint8_t *key_hash = NULL;
  uint8_t *key_data = NULL;
  size_t key_len = 0;
  int ret = 0;

  // if there is a file named <databasename>.key, we use this key in addition to the password.
  // otherwise, only the password is used to unlock the database.
  keyfd = fopen(kdbx_filename, "rb");

  if (!keyfd) {
    printf("[*] Not using keyfile\n");
    key_hash = NULL;
  } else {
    printf("[*] Using keyfile %s\n", kdbx_filename);
    key_hash = (uint8_t *)malloc(32);
    if(!key_hash) {
      printf("[!] key_hash = malloc(32) failed.");
      return false;
    }

    fseek(keyfd, 0, SEEK_END);
    key_len = ftell(keyfd);
    fseek(keyfd, 0, SEEK_SET);
    key_data = (uint8_t *)malloc(key_len);

    if(!key_data) {
      printf("[!] key_data = malloc(%d) failed.", key_len);
      return false;
    }

    ret = fread(key_data, key_len, 1, keyfd);

    if ( ret != 1)
      printf("[!] fread(key_data) failed.");

    sha256_hash(key_hash, key_data, key_len);
    printf("[+] key hash:               "); print_hex_buf(key_hash, 32); puts("");
  }

  printf("[*] kdbx crack:\n");

  if( wordlist_fd == NULL )
    return false;

  while( fgets(pass, sizeof(pass), wordlist_fd) ) {
    int len = strlen(pass);
    if(len > 0)
      pass[len-1] = 0x00;

    res = kdbx_decrypt_payload(db, pass, key_hash);
    if(res) {
      printf("[*] decryption successful with password %s\n", pass);
      break;
    }
  }

  return res;
}

bool kdbx_decrypt_payload(m0_kdbx_database_t *db, char *pass, uint8_t *key_hash)
{
  bool res = false;
  uint8_t           hash[32] = {0};
  uint8_t  composite_key[32] = {0};
  uint8_t composite_data[64] = {0};
  uint8_t  transform_key[32] = {0};
  uint8_t     master_key[32] = {0};
  uint8_t   *masterkey_input = NULL;
  size_t masterkey_input_len = 0;

  m0_kdbx_header_entry_t *hdr = &db->kdbxheader;

  memset(composite_data, 0, 64);
  memset(transform_key, 0, 32);
  memset(master_key, 0, 32);

  printf("[+] trying: %s\r", pass);

  sha256_hash(hash, pass, strlen(pass));

  if(key_hash == NULL) {
    sha256_hash(composite_key, hash, sizeof(hash));
  } else {
    memcpy(composite_data, hash, sizeof(hash));
    memcpy(composite_data+sizeof(hash), key_hash, sizeof(composite_data)-sizeof(hash));
    sha256_hash(composite_key, composite_data, sizeof(composite_data));
  }

  memcpy(transform_key, composite_key, sizeof(transform_key));

  // aes_transformkey() is platform specific.
  // For Windows, CNG is used and implemented in crypto-ms.c
  aes_transformkey(&db->kdbxheader, transform_key, sizeof(transform_key));

  sha256_hash(transform_key, transform_key, sizeof(transform_key));

  masterkey_input_len = sizeof(transform_key) + hdr[MASTERSEED].len;
  masterkey_input     = (uint8_t *)malloc(masterkey_input_len);

  if(masterkey_input_len < hdr[MASTERSEED].len) {
    // should never happen, as masterkey len is (currently) 16 bit
    puts("[!] masterkey_input len integer overflow.");
    return 0;
  }
  memcpy(masterkey_input, hdr[MASTERSEED].data, hdr[MASTERSEED].len);
  memcpy(masterkey_input+hdr[MASTERSEED].len, transform_key, sizeof(transform_key));

  sha256_hash(master_key, masterkey_input, masterkey_input_len);

  // aes_decrypt_check() is platform specific.
  // For Windows, CNG is used and implemented in crypto-ms.c
  res = aes_decrypt_check(hdr, master_key, &db->payload);

  return res;
}

int main(int ac, char** av)
{
  FILE *kdbx_fd = NULL;
  FILE *wordlist_fd = NULL;

  char *kdbx_path = NULL;
  char *tmp = NULL;
  char *wordlist_path = NULL;
  size_t filename_len = 0;

  m0_kdbx_database_t      kdbx_db = {0};

  if(ac < 2)
    usage(av[0]);
  else if(ac > 2) {
    // wordlist from file
    wordlist_path = av[2];
  } else {
    // wordlist == stdin
  }

  memset(&kdbx_db, 0, sizeof(kdbx_db));

  kdbx_path = av[1];
  filename_len = strlen(kdbx_path);
  kdbx_filename = (char *) malloc(filename_len + 5);
  memset(kdbx_filename, 0, filename_len+5);

  if(filename_len > filename_len+5)
    exit(1);

  memcpy(kdbx_filename, kdbx_path, filename_len);
  tmp = strrchr(kdbx_filename, '.');

  if(tmp)
    memcpy(tmp, ".key\x00", 5);
  else
    strcat(kdbx_filename, ".key");

  printf("[*] using  db: %s\n[*] using key: %s\n", kdbx_path, kdbx_filename);

  kdbx_fd = fopen(kdbx_path, "rb");

  if (!kdbx_fd) {
    printf("[!] Can't open kdbx %s\n", kdbx_path);
    exit(2);
  }

  if(wordlist_path) {
    wordlist_fd = fopen(wordlist_path, "r");
    if (!wordlist_fd) {
      printf("[!] Can't open wordlist %s\n", wordlist_path);
      exit(2);
    }
  } else {
    wordlist_fd = stdin; //fdopen(stdin, "r");
    if (!wordlist_fd) {
      printf("[!] Can't open wordlist from stdin\n");
      exit(2);
    }
  }

  kdbx_header_read(kdbx_fd, &kdbx_db.fileheader);
  kdbx_header_dump(kdbx_db.fileheader);

  kdbx_headerentries_read(kdbx_fd, &kdbx_db.kdbxheader);
  kdbx_headerentries_dump(&kdbx_db.kdbxheader);

  kdbx_payload_read(kdbx_fd, &kdbx_db.payload);
  kdbx_payload_dump(kdbx_db.payload);

  kdbx_payload_crack(&kdbx_db, wordlist_fd);

  kdbx_headerentries_free(&kdbx_db.kdbxheader);
  fclose(kdbx_fd);
  exit(0);
}

static void usage(char *prog)
{
  printf("[+] usage: %s <keepassx-file.kdbx> ...\n", prog);
  exit(1);
}