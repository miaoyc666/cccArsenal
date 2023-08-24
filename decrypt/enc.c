/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_COMP
# include <openssl/comp.h>
#endif
#include <ctype.h>

#include "apps.h"

#undef SIZE
#undef BSIZE
#define SIZE    (512)
#define BSIZE   (8*1024)


int AES_CBC_256_desrypt(char* infile, char* outfile, char *str)
{
    static char buf[128];
    static const char magic[] = "Salted__";
    ENGINE *e = NULL;
    BIO *in = NULL, *out = NULL, *b64 = NULL, *benc = NULL, *rbio =
        NULL, *wbio = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL, *c;
    const EVP_MD *dgst = NULL;
    char *hkey = NULL, *hiv = NULL, *hsalt = NULL, *p;
    char *passarg = NULL, *pass = NULL, *strbuf = NULL;
    char mbuf[sizeof(magic) - 1];
    int bsize = BSIZE, verbose = 0, debug = 0, olb64 = 0, nosalt = 0;
    int i, k;
    int base64 = 0, informat = FORMAT_BINARY, outformat = FORMAT_BINARY;
    int ret = 1, inl = 0;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char *buff = NULL, salt[PKCS5_SALT_LEN];
    int pbkdf2 = 0;
    int iter = 0;
    long n;

    /* first check the program name */

    /* It must be large enough for a base64 encoded line */
    strbuf = app_malloc(SIZE, "strbuf");
    buff = app_malloc(EVP_ENCODE_LENGTH(bsize), "evp buffer");

    // start
    cipher = EVP_aes_256_cbc();
    dgst = EVP_sha256();
    int enc = 0;
    int printkey = 1;
    in = bio_open_default(infile, 'r', informat);
    out = bio_open_default(outfile, 'w', outformat);
    rbio = in;
    wbio = out;

    if (cipher != NULL) {
        /*
         * Note that str is NULL if a key was passed on the command line, so
         * we get no salt in that case. Is this a bug?
         */
        if (str != NULL) {
            /*
             * Salt handling: if encrypting generate a salt and write to
             * output BIO. If decrypting read salt from input BIO.
             */
            unsigned char *sptr;
            size_t str_len = strlen(str);
            BIO_read(rbio, mbuf, sizeof(mbuf));
            BIO_read(rbio, (unsigned char *)salt, sizeof(salt));

            sptr = salt;

            if (!EVP_BytesToKey(cipher, dgst, sptr,
                                (unsigned char *)str, str_len,
                                1, key, iv)) {
                printf("EVP_BytesToKey failed\n");
                goto end;
            }
            /*
             * zero the complete buffer or the string passed from the command
             * line.
             */
            OPENSSL_cleanse(str, str_len);
        }

        if ((benc = BIO_new(BIO_f_cipher())) == NULL)
            goto end;

        /*
         * Since we may be changing parameters work on the encryption context
         * rather than calling BIO_set_cipher().
         */

        BIO_get_cipher_ctx(benc, &ctx);

        if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc)) {
            printf("Error setting cipher %s\n", EVP_CIPHER_name(cipher));
            goto end;
        }

        if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc)) {
            printf("Error setting cipher %s\n", EVP_CIPHER_name(cipher));
            goto end;
        }

        if (printkey) {
            if (!nosalt) {
                printf("salt=");
                for (i = 0; i < (int)sizeof(salt); i++)
                    printf("%02X", salt[i]);
                printf("\n");
            }
            if (EVP_CIPHER_key_length(cipher) > 0) {
                printf("key=");
                for (i = 0; i < EVP_CIPHER_key_length(cipher); i++)
                    printf("%02X", key[i]);
                printf("\n");
            }
            if (EVP_CIPHER_iv_length(cipher) > 0) {
                printf("iv =");
                for (i = 0; i < EVP_CIPHER_iv_length(cipher); i++)
                    printf("%02X", iv[i]);
                printf("\n");
            }
            if (printkey == 2) {
                ret = 0;
                goto end;
            }
        }
    }

    /* Only encrypt/decrypt as we write the file */
    if (benc != NULL)
        wbio = BIO_push(benc, wbio);

    while (BIO_pending(rbio) || !BIO_eof(rbio)) {
        inl = BIO_read(rbio, (char *)buff, bsize);
        if (inl <= 0)
            break;
        if (BIO_write(wbio, (char *)buff, inl) != inl) {
            printf("error writing output file\n");
            goto end;
        }
    }
    if (!BIO_flush(wbio)) {
        printf("bad decrypt\n");
        goto end;
    }
    ret = 0;
 end:
    OPENSSL_free(strbuf);
    OPENSSL_free(buff);
    BIO_free(in);
    BIO_free_all(out);
    BIO_free(benc);
    BIO_free(b64);
    OPENSSL_free(pass);
    return ret;
}

// int main() {
//     const char* infile = "1";
//     const char* outfile = "2";
//     const unsigned char key[] = "347eab6904531401";
//     desrypt(infile, outfile, key);
//     return 0;
// }
