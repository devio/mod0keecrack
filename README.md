# mod0keecrack

## Introduction

> *KeePass is a free open source password manager, which helps you to manage your passwords in a secure way. You can put all your passwords in one database, which is locked with one master key or a key file.*
(Source: http://keepass.info/)

**mod0keecrack** is a simple tool to crack/bruteforce passwords of KeePass 2 databases. It implements a KeePass 2 Database file parser for .kdbx files, as well as decryption routines to verify if a supplied password is correct. mod0keecrack only handles the encrypted file format and is not able to parse the resulting plaintext database. The only purpose of mod0keecrack is the brute-forcing of a KeePass 2 database password.

mod0keecrack handles KeePass 2 databases that are encrypted with password-only, or with password and key-file.

Currently, there is no incremental or template-based bruteforce algorithm for passphrase generation implemented yet. To use mod0keecrack, you need to generate own wordlists or supply a wordlist via pipe/stdin. For example, you could use the john password cracker to generate wordlists and feed them directly into mod0keecrack via stdin. You can also use text-files with a wordlist on the command-line.

Using wordlists is recommended, as dumb incremental brute-force may take a too long time due to the crypto-algorithms that are used by KeePass databases (SHA256 and many AES key-transformation rounds). 

mod0keecrack is plain C and has no 3rd party library dependencies on Windows, as it's using the Microsoft Cryptographic (CNG) Framework. A platform independent implementation could be done by simply porting crypto-ms.c to e.g. crypto-openssl.c.

## Usage

To encrypt password databases, KeePass supports passwords, keyfiles or a password-keyfile combo. To crack a password-only database, use mod0keecrack like this:

`mod0keecrack <keepassx-file.kdbx> [wordlist.txt]`

To crack a database that also uses a key-file, use the command line as shown above, and copy the keyfile to the same directory as the database and rename it to <databasename>.key. For example, if your KeePass database filename is `lala.kdbx` you must copy the keyfile to `lala.key` within the same directory. **If there is a corresponding .key file within the same directory, mod0keecrack always consider it as key-file input.**

wordlist.txt is optional. If no wordlist is provided via command line argument, mod0keecrack reads a wordlist from stdin. If you want to generate a wordlist on the fly, you can use genwords.py as an example and use it like this:

`genwords.py Secrets%04d! | mod0keecrack lala.kdbx`

Example output of the last command line (lala.kdbx uses password AND keyfile lala.key):

<pre>
mod0keecrack>genwords.py Secrets%04d! | mod0keecrack.exe lala.kdbx
[*] using  db: lala.kdbx
[*] using key: lala.key
[*] kdbx header:
[-]    file magic:          9aa2d903
[-]    file identifier:     b54bfb67
[-]    file minor version:  0001
[-]    file major version:  0003
[*] kdbx headerentries:
[-]    END:                 0D0A0D0A
[-]    COMMENT:
[-]    CIPHERID:            31C1F2E6BF714350BE5805216AFC5AFF
[-]    COMPRESSIONFLAGS:    00000001
[-]    MASTERSEED:          BD5A62AC01FD27B040D98894A7FA306D0F9AED7A23E870DC1E36ECE31DA2526B
[-]    TRANSFORMSEED:       FFA6509325D87EDD8FAFA2A44C814F8846109FC1F7BCF2775F278C1C0CDF52A7
[-]    TRANSFORMROUNDS:     00000000000186a0
[-]    ENCRYPTIONIV:        40F71E30D138591E5F8AF4EDF1DB9EE0
[-]    PROTECTEDSTREAMKEY:  27CA955DF72F13301E1A038404ADCA4D59E8DC26B30F8776E393F0F22568E13E
[-]    STREAMSTARTBYTES:    76B99E10BE00334DDE830361A07FBA86845F39DD0DCBCEEE5102D6F41204B746
[-]    INNERRANDOMSTREAMID: 00000002
[*] kdbx payload:
[-]    payload offset:      de
[-]    payload len:         470
[*] Using keyfile lala.key
[+] key hash:               A884B77F5E1ED180BDF95B988BD032247CE6A87893BB4CC5C0532407BC86FE3B
[*] kdbx crack:
[*] decryption successful with password Secrets2015!
</pre>

mod0keecrack does not process decrypted kdbx-database payload. It simply tells you, if a database-passphrase was right or wrong.

## Platforms

mod0keecrack is implemented in plain C and should be able to compile and run on any platform, if the crypto-framework is ported to the target platform. Currently, the only platform dependend code is implemented in three functions in crypto-ms.c. The first version is using the Microsoft CNG (bcrypt) framework for SHA256 and AES. It should be no issue to implement a platform independent openssl-based version of crypto-ms.c.

## Building

To build mod0keecrack on Windows, open your Dev-command prompt and enter:

`cl.exe /Femod0keecrack.exe helper.c mod0keecrack.c crypto-ms.c bcrypt.lib`

## Author and Legal Stuff

mod0keecrack was written by Thorsten (THS) Schroeder of modzero. You can get in touch with me e.g. via twitter: `@__ths__`

<pre>
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
</pre>

