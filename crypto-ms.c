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
 * File: crypto-ms.c
 * Description: Platform specific implementation of keepassx crypto functions
 *              on Microsoft Windows.
 */

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <stdbool.h>

#include "helper.h"
#include "mod0keecrack.h"

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

int aes_transformkey(m0_kdbx_header_entry_t *hdr, uint8_t *tkey, size_t tkeylen)
{
  BCRYPT_ALG_HANDLE aes            = NULL;
  BCRYPT_KEY_HANDLE key            = NULL;
  NTSTATUS          status         = 0;
  DWORD             len_ciphertext = 0,
                    tmp_len        = 0,
                    key_objectlen  = 0;

  PBYTE             key_object     = NULL;
  uint64_t          rounds         = 0;

  // Open an algorithm handle.
  status = BCryptOpenAlgorithmProvider(
                &aes,
                BCRYPT_AES_ALGORITHM,
                NULL,
                0);

  if(!NT_SUCCESS(status)) {
    printf("[!] Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
    goto cleanup;
  }

  // Calculate the size of the buffer to hold the KeyObject.
  status = BCryptGetProperty(
                aes,
                BCRYPT_OBJECT_LENGTH,
                (PBYTE)&key_objectlen,
                sizeof(DWORD),
                &tmp_len,
                0);

  if(!NT_SUCCESS(status)) {
    printf("[!] Error 0x%x returned by BCryptGetProperty\n", status);
    goto cleanup;
  }

  // Allocate the key object on the heap.
  key_object = (PBYTE)HeapAlloc(GetProcessHeap(), 0, key_objectlen);

  if(NULL == key_object)     {
    printf("[!] memory allocation failed\n");
    goto cleanup;
  }

  status = BCryptSetProperty(
                aes,
                BCRYPT_CHAINING_MODE,
                (PBYTE)BCRYPT_CHAIN_MODE_ECB,
                sizeof(BCRYPT_CHAIN_MODE_ECB),
                0);

  if(!NT_SUCCESS(status)) {
    printf("[!] Error 0x%x returned by BCryptSetProperty\n", status);
    goto cleanup;
  }

  // Generate the key from supplied input key bytes.
  status = BCryptGenerateSymmetricKey(
                aes,
                &key,
                key_object,
                key_objectlen,
                hdr[TRANSFORMSEED].data,
                hdr[TRANSFORMSEED].len,
                0);

  if(!NT_SUCCESS(status)) {
    printf("[!] Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
    goto cleanup;
  }

  status = BCryptEncrypt(
                key,
                tkey,
                tkeylen,
                NULL,
                NULL,
                0,
                NULL,
                0,
                &len_ciphertext,
                0);

  if(!NT_SUCCESS(status)) {
    printf("[!] Error 0x%x returned by BCryptEncrypt (calculate)\n", status);
    goto cleanup;
  }

  for(rounds = 0; rounds < hdr[TRANSFORMROUNDS].qw; rounds++) {

    status = BCryptEncrypt(
                key,
                tkey,
                tkeylen,
                NULL,
                NULL,
                0,
                tkey,
                tkeylen,
                &tmp_len,
                0);

    if(!NT_SUCCESS(status)) {
      printf("[!] Error 0x%x returned by BCryptEncrypt (encrypt)\n", status);
      goto cleanup;
    }
  }

cleanup:

  if(aes) {
    BCryptCloseAlgorithmProvider(aes,0);
  }

  if (key) {
    BCryptDestroyKey(key);
  }

  if(key_object) {
    HeapFree(GetProcessHeap(), 0, key_object);
  }

  return status;
}

bool aes_decrypt_check(m0_kdbx_header_entry_t *hdr, uint8_t *masterkey, m0_kdbx_payload_t *payload)
{
  bool res = false;

  BCRYPT_ALG_HANDLE aes            = NULL;
  BCRYPT_KEY_HANDLE ctx            = NULL;
  NTSTATUS          status         = 0;
  DWORD             len_ciphertext = 0,
                    tmp_len        = 0,
                    key_objectlen  = 0;

  PBYTE             key_object     = NULL;

  uint8_t           plaintext[32]  = {0};
  uint8_t           iv[256]        = {0};
  uint8_t           ivlen          = hdr[ENCRYPTIONIV].len & 0xFF;

  // we need to create a local copy of IV, as it is modified during decryption.
  memcpy(&iv, hdr[ENCRYPTIONIV].data, ivlen);

  // Open an algorithm handle.
  status = BCryptOpenAlgorithmProvider(
                  &aes,
                  BCRYPT_AES_ALGORITHM,
                  NULL,
                  0);

  if(!NT_SUCCESS(status)) {
    printf("[!] Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
    goto cleanup;
  }

  // Calculate the size of the buffer to hold the Key Object.
  status = BCryptGetProperty(
                  aes,
                  BCRYPT_OBJECT_LENGTH,
                  (PBYTE)&key_objectlen,
                  sizeof(DWORD),
                  &tmp_len,
                  0);

  if(!NT_SUCCESS(status)) {
    printf("[!] Error 0x%x returned by BCryptGetProperty\n", status);
    goto cleanup;
  }

  // We should use preallocated memory for better performance...
  key_object = (PBYTE)HeapAlloc(GetProcessHeap(), 0, key_objectlen);

  if(NULL == key_object) {
    printf("[!] memory allocation failed\n");
    goto cleanup;
  }

  status = BCryptSetProperty(
                  aes,
                  BCRYPT_CHAINING_MODE,
                  (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                  sizeof(BCRYPT_CHAIN_MODE_CBC),
                  0);

  if(!NT_SUCCESS(status)) {
    printf("[!] Error 0x%x returned by BCryptSetProperty\n", status);
    goto cleanup;
  }

  // Generate the key from supplied input key bytes.
  status = BCryptGenerateSymmetricKey(
                  aes,
                  &ctx,
                  key_object,
                  key_objectlen,
                  masterkey,
                  32,
                  0);

  if(!NT_SUCCESS(status)) {
    printf("[!] Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
    goto cleanup;
  }

  status = BCryptDecrypt(
                  ctx,
                  payload->encrypted,
                  hdr[STREAMSTARTBYTES].len,
                  NULL,
                  iv,
                  ivlen,
                  plaintext,
                  sizeof(plaintext),
                  &tmp_len,
                  0);

  if(!NT_SUCCESS(status)) {
    printf("[!] Error 0x%x returned by BCryptDecrypt\n", status);
    goto cleanup;
  }

  // success!
  if (0 == memcmp(plaintext, hdr[STREAMSTARTBYTES].data, hdr[STREAMSTARTBYTES].len)) {
    res = true;
    payload->decrypted = malloc(hdr[STREAMSTARTBYTES].len);
    memcpy(payload->decrypted, plaintext, hdr[STREAMSTARTBYTES].len);
  }

cleanup:

  if(aes) {
    BCryptCloseAlgorithmProvider(aes,0);
  }

  if (ctx) {
    BCryptDestroyKey(ctx);
  }

  if(key_object) {
    HeapFree(GetProcessHeap(), 0, key_object);
  }

  return res;
}


int sha256_hash(uint8_t *hash, uint8_t *data, size_t len)
{
  int res = 0;
  NTSTATUS    status;
  BCRYPT_ALG_HANDLE   sha = NULL;
  BCRYPT_HASH_HANDLE  ctx = NULL;

  status = BCryptOpenAlgorithmProvider(
              &sha,
              BCRYPT_SHA256_ALGORITHM,
              NULL,
              BCRYPT_HASH_REUSABLE_FLAG);

  status = BCryptCreateHash(
              sha,
              &ctx,
              NULL,
              0,
              NULL,
              0,
              0);

  status = BCryptHashData(
              ctx,
              (PBYTE)data,
              len,
              0);

  status = BCryptFinishHash(
              ctx,
              hash,
              32,
              0);

cleanup:

  if (NULL != ctx) {
    BCryptDestroyHash(ctx);
  }

  if( NULL != sha ) {
    BCryptCloseAlgorithmProvider(
              sha,
              0);
  }

  return res;

}

