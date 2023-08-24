/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(_POSIX_C_SOURCE) && defined(OPENSSL_SYS_VMS)
/*
 * On VMS, you need to define this to get the declaration of fileno().  The
 * value 2 is to make sure no function defined in POSIX-2 is left undefined.
 */
# define _POSIX_C_SOURCE 2
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifndef OPENSSL_NO_POSIX_IO
# include <sys/stat.h>
# include <fcntl.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include "apps.h"

#ifdef _WIN32
static int WIN32_rename(const char *from, const char *to);
# define rename(from,to) WIN32_rename((from),(to))
#endif

#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
# include <conio.h>
#endif

#if defined(OPENSSL_SYS_MSDOS) && !defined(_WIN32)
# define _kbhit kbhit
#endif

typedef struct {
    const char *name;
    unsigned long flag;
    unsigned long mask;
} NAME_EX_TBL;

static UI_METHOD *ui_method = NULL;
static const UI_METHOD *ui_fallback_method = NULL;

static int set_table_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl);
static int set_multi_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl);

int app_init(long mesgwin);

int chopup_args(ARGS *arg, char *buf)
{
    int quoted;
    char c = '\0', *p = NULL;

    arg->argc = 0;
    if (arg->size == 0) {
        arg->size = 20;
        arg->argv = app_malloc(sizeof(*arg->argv) * arg->size, "argv space");
    }

    for (p = buf;;) {
        /* Skip whitespace. */
        while (*p && isspace(_UC(*p)))
            p++;
        if (!*p)
            break;

        /* The start of something good :-) */
        if (arg->argc >= arg->size) {
            char **tmp;
            arg->size += 20;
            tmp = OPENSSL_realloc(arg->argv, sizeof(*arg->argv) * arg->size);
            if (tmp == NULL)
                return 0;
            arg->argv = tmp;
        }
        quoted = *p == '\'' || *p == '"';
        if (quoted)
            c = *p++;
        arg->argv[arg->argc++] = p;

        /* now look for the end of this */
        if (quoted) {
            while (*p && *p != c)
                p++;
            *p++ = '\0';
        } else {
            while (*p && !isspace(_UC(*p)))
                p++;
            if (*p)
                *p++ = '\0';
        }
    }
    arg->argv[arg->argc] = NULL;
    return 1;
}

#ifndef APP_INIT
int app_init(long mesgwin)
{
    return 1;
}
#endif

int ctx_set_verify_locations(SSL_CTX *ctx, const char *CAfile,
                             const char *CApath, int noCAfile, int noCApath)
{
    if (CAfile == NULL && CApath == NULL) {
        if (!noCAfile && SSL_CTX_set_default_verify_file(ctx) <= 0)
            return 0;
        if (!noCApath && SSL_CTX_set_default_verify_dir(ctx) <= 0)
            return 0;

        return 1;
    }
    return SSL_CTX_load_verify_locations(ctx, CAfile, CApath);
}

#ifndef OPENSSL_NO_CT

int ctx_set_ctlog_list_file(SSL_CTX *ctx, const char *path)
{
    if (path == NULL)
        return SSL_CTX_set_default_ctlog_list_file(ctx);

    return SSL_CTX_set_ctlog_list_file(ctx, path);
}

#endif

static unsigned long nmflag = 0;
static char nmflag_set = 0;

int set_nameopt(const char *arg)
{
    int ret = set_name_ex(&nmflag, arg);

    if (ret)
        nmflag_set = 1;

    return ret;
}

unsigned long get_nameopt(void)
{
    return (nmflag_set) ? nmflag : XN_FLAG_ONELINE;
}

int dump_cert_text(BIO *out, X509 *x)
{
    print_name(out, "subject=", X509_get_subject_name(x), get_nameopt());
    BIO_puts(out, "\n");
    print_name(out, "issuer=", X509_get_issuer_name(x), get_nameopt());
    BIO_puts(out, "\n");

    return 0;
}

static int ui_open(UI *ui)
{
    int (*opener)(UI *ui) = UI_method_get_opener(ui_fallback_method);

    if (opener)
        return opener(ui);
    return 1;
}

static int ui_read(UI *ui, UI_STRING *uis)
{
    int (*reader)(UI *ui, UI_STRING *uis) = NULL;

    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
        && UI_get0_user_data(ui)) {
        switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY:
            {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;
                if (password && password[0] != '\0') {
                    UI_set_result(ui, uis, password);
                    return 1;
                }
            }
            break;
        case UIT_NONE:
        case UIT_BOOLEAN:
        case UIT_INFO:
        case UIT_ERROR:
            break;
        }
    }

    reader = UI_method_get_reader(ui_fallback_method);
    if (reader)
        return reader(ui, uis);
    return 1;
}

static int ui_write(UI *ui, UI_STRING *uis)
{
    int (*writer)(UI *ui, UI_STRING *uis) = NULL;

    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
        && UI_get0_user_data(ui)) {
        switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY:
            {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;
                if (password && password[0] != '\0')
                    return 1;
            }
            break;
        case UIT_NONE:
        case UIT_BOOLEAN:
        case UIT_INFO:
        case UIT_ERROR:
            break;
        }
    }

    writer = UI_method_get_writer(ui_fallback_method);
    if (writer)
        return writer(ui, uis);
    return 1;
}

static int ui_close(UI *ui)
{
    int (*closer)(UI *ui) = UI_method_get_closer(ui_fallback_method);

    if (closer)
        return closer(ui);
    return 1;
}

int setup_ui_method(void)
{
    ui_fallback_method = UI_null();
#ifndef OPENSSL_NO_UI_CONSOLE
    ui_fallback_method = UI_OpenSSL();
#endif
    ui_method = UI_create_method("OpenSSL application user interface");
    UI_method_set_opener(ui_method, ui_open);
    UI_method_set_reader(ui_method, ui_read);
    UI_method_set_writer(ui_method, ui_write);
    UI_method_set_closer(ui_method, ui_close);
    return 0;
}

void destroy_ui_method(void)
{
    if (ui_method) {
        UI_destroy_method(ui_method);
        ui_method = NULL;
    }
}

const UI_METHOD *get_ui_method(void)
{
    return ui_method;
}

void* app_malloc(int sz, const char *what)
{
    void *vp = OPENSSL_malloc(sz);

    if (vp == NULL) {
        printf("Could not allocate %d bytes for %s\n", sz, what);
        exit(1);
    }
    return vp;
}

#define X509V3_EXT_UNKNOWN_MASK         (0xfL << 16)
/* Return error for unknown extensions */
#define X509V3_EXT_DEFAULT              0
/* Print error for unknown extensions */
#define X509V3_EXT_ERROR_UNKNOWN        (1L << 16)
/* ASN1 parse unknown extensions */
#define X509V3_EXT_PARSE_UNKNOWN        (2L << 16)
/* BIO_dump unknown extensions */
#define X509V3_EXT_DUMP_UNKNOWN         (3L << 16)

#define X509_FLAG_CA (X509_FLAG_NO_ISSUER | X509_FLAG_NO_PUBKEY | \
                         X509_FLAG_NO_HEADER | X509_FLAG_NO_VERSION)

int set_cert_ex(unsigned long *flags, const char *arg)
{
    static const NAME_EX_TBL cert_tbl[] = {
        {"compatible", X509_FLAG_COMPAT, 0xffffffffl},
        {"ca_default", X509_FLAG_CA, 0xffffffffl},
        {"no_header", X509_FLAG_NO_HEADER, 0},
        {"no_version", X509_FLAG_NO_VERSION, 0},
        {"no_serial", X509_FLAG_NO_SERIAL, 0},
        {"no_signame", X509_FLAG_NO_SIGNAME, 0},
        {"no_validity", X509_FLAG_NO_VALIDITY, 0},
        {"no_subject", X509_FLAG_NO_SUBJECT, 0},
        {"no_issuer", X509_FLAG_NO_ISSUER, 0},
        {"no_pubkey", X509_FLAG_NO_PUBKEY, 0},
        {"no_extensions", X509_FLAG_NO_EXTENSIONS, 0},
        {"no_sigdump", X509_FLAG_NO_SIGDUMP, 0},
        {"no_aux", X509_FLAG_NO_AUX, 0},
        {"no_attributes", X509_FLAG_NO_ATTRIBUTES, 0},
        {"ext_default", X509V3_EXT_DEFAULT, X509V3_EXT_UNKNOWN_MASK},
        {"ext_error", X509V3_EXT_ERROR_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {"ext_parse", X509V3_EXT_PARSE_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {"ext_dump", X509V3_EXT_DUMP_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {NULL, 0, 0}
    };
    return set_multi_opts(flags, arg, cert_tbl);
}

int set_name_ex(unsigned long *flags, const char *arg)
{
    static const NAME_EX_TBL ex_tbl[] = {
        {"esc_2253", ASN1_STRFLGS_ESC_2253, 0},
        {"esc_2254", ASN1_STRFLGS_ESC_2254, 0},
        {"esc_ctrl", ASN1_STRFLGS_ESC_CTRL, 0},
        {"esc_msb", ASN1_STRFLGS_ESC_MSB, 0},
        {"use_quote", ASN1_STRFLGS_ESC_QUOTE, 0},
        {"utf8", ASN1_STRFLGS_UTF8_CONVERT, 0},
        {"ignore_type", ASN1_STRFLGS_IGNORE_TYPE, 0},
        {"show_type", ASN1_STRFLGS_SHOW_TYPE, 0},
        {"dump_all", ASN1_STRFLGS_DUMP_ALL, 0},
        {"dump_nostr", ASN1_STRFLGS_DUMP_UNKNOWN, 0},
        {"dump_der", ASN1_STRFLGS_DUMP_DER, 0},
        {"compat", XN_FLAG_COMPAT, 0xffffffffL},
        {"sep_comma_plus", XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_MASK},
        {"sep_comma_plus_space", XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK},
        {"sep_semi_plus_space", XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SEP_MASK},
        {"sep_multiline", XN_FLAG_SEP_MULTILINE, XN_FLAG_SEP_MASK},
        {"dn_rev", XN_FLAG_DN_REV, 0},
        {"nofname", XN_FLAG_FN_NONE, XN_FLAG_FN_MASK},
        {"sname", XN_FLAG_FN_SN, XN_FLAG_FN_MASK},
        {"lname", XN_FLAG_FN_LN, XN_FLAG_FN_MASK},
        {"align", XN_FLAG_FN_ALIGN, 0},
        {"oid", XN_FLAG_FN_OID, XN_FLAG_FN_MASK},
        {"space_eq", XN_FLAG_SPC_EQ, 0},
        {"dump_unknown", XN_FLAG_DUMP_UNKNOWN_FIELDS, 0},
        {"RFC2253", XN_FLAG_RFC2253, 0xffffffffL},
        {"oneline", XN_FLAG_ONELINE, 0xffffffffL},
        {"multiline", XN_FLAG_MULTILINE, 0xffffffffL},
        {"ca_default", XN_FLAG_MULTILINE, 0xffffffffL},
        {NULL, 0, 0}
    };
    if (set_multi_opts(flags, arg, ex_tbl) == 0)
        return 0;
    if (*flags != XN_FLAG_COMPAT
        && (*flags & XN_FLAG_SEP_MASK) == 0)
        *flags |= XN_FLAG_SEP_CPLUS_SPC;
    return 1;
}

int set_ext_copy(int *copy_type, const char *arg)
{
    if (strcasecmp(arg, "none") == 0)
        *copy_type = EXT_COPY_NONE;
    else if (strcasecmp(arg, "copy") == 0)
        *copy_type = EXT_COPY_ADD;
    else if (strcasecmp(arg, "copyall") == 0)
        *copy_type = EXT_COPY_ALL;
    else
        return 0;
    return 1;
}

int copy_extensions(X509 *x, X509_REQ *req, int copy_type)
{
    STACK_OF(X509_EXTENSION) *exts = NULL;
    X509_EXTENSION *ext, *tmpext;
    ASN1_OBJECT *obj;
    int i, idx, ret = 0;
    if (!x || !req || (copy_type == EXT_COPY_NONE))
        return 1;
    exts = X509_REQ_get_extensions(req);

    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        ext = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ext);
        idx = X509_get_ext_by_OBJ(x, obj, -1);
        /* Does extension exist? */
        if (idx != -1) {
            /* If normal copy don't override existing extension */
            if (copy_type == EXT_COPY_ADD)
                continue;
            /* Delete all extensions of same type */
            do {
                tmpext = X509_get_ext(x, idx);
                X509_delete_ext(x, idx);
                X509_EXTENSION_free(tmpext);
                idx = X509_get_ext_by_OBJ(x, obj, -1);
            } while (idx != -1);
        }
        if (!X509_add_ext(x, ext, -1))
            goto end;
    }

    ret = 1;

 end:

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    return ret;
}

static int set_multi_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl)
{
    STACK_OF(CONF_VALUE) *vals;
    CONF_VALUE *val;
    int i, ret = 1;
    if (!arg)
        return 0;
    vals = X509V3_parse_list(arg);
    for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
        val = sk_CONF_VALUE_value(vals, i);
        if (!set_table_opts(flags, val->name, in_tbl))
            ret = 0;
    }
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    return ret;
}

static int set_table_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl)
{
    char c;
    const NAME_EX_TBL *ptbl;
    c = arg[0];

    if (c == '-') {
        c = 0;
        arg++;
    } else if (c == '+') {
        c = 1;
        arg++;
    } else {
        c = 1;
    }

    for (ptbl = in_tbl; ptbl->name; ptbl++) {
        if (strcasecmp(arg, ptbl->name) == 0) {
            *flags &= ~ptbl->mask;
            if (c)
                *flags |= ptbl->flag;
            else
                *flags &= ~ptbl->flag;
            return 1;
        }
    }
    return 0;
}

void print_name(BIO *out, const char *title, X509_NAME *nm,
                unsigned long lflags)
{
    char *buf;
    char mline = 0;
    int indent = 0;

    if (title)
        BIO_puts(out, title);
    if ((lflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mline = 1;
        indent = 4;
    }
    if (lflags == XN_FLAG_COMPAT) {
        buf = X509_NAME_oneline(nm, 0, 0);
        BIO_puts(out, buf);
        BIO_puts(out, "\n");
        OPENSSL_free(buf);
    } else {
        if (mline)
            BIO_puts(out, "\n");
        X509_NAME_print_ex(out, nm, indent, lflags);
        BIO_puts(out, "\n");
    }
}

void print_bignum_var(BIO *out, const BIGNUM *in, const char *var,
                      int len, unsigned char *buffer)
{
    BIO_printf(out, "    static unsigned char %s_%d[] = {", var, len);
    if (BN_is_zero(in)) {
        BIO_printf(out, "\n        0x00");
    } else {
        int i, l;

        l = BN_bn2bin(in, buffer);
        for (i = 0; i < l; i++) {
            BIO_printf(out, (i % 10) == 0 ? "\n        " : " ");
            if (i < l - 1)
                BIO_printf(out, "0x%02X,", buffer[i]);
            else
                BIO_printf(out, "0x%02X", buffer[i]);
        }
    }
    BIO_printf(out, "\n    };\n");
}

void print_array(BIO *out, const char* title, int len, const unsigned char* d)
{
    int i;

    BIO_printf(out, "unsigned char %s[%d] = {", title, len);
    for (i = 0; i < len; i++) {
        if ((i % 10) == 0)
            BIO_printf(out, "\n    ");
        if (i < len - 1)
            BIO_printf(out, "0x%02X, ", d[i]);
        else
            BIO_printf(out, "0x%02X", d[i]);
    }
    BIO_printf(out, "\n};\n");
}

static unsigned long index_serial_hash(const OPENSSL_CSTRING *a)
{
    const char *n;

    n = a[DB_serial];
    while (*n == '0')
        n++;
    return OPENSSL_LH_strhash(n);
}

static int index_serial_cmp(const OPENSSL_CSTRING *a,
                            const OPENSSL_CSTRING *b)
{
    const char *aa, *bb;

    for (aa = a[DB_serial]; *aa == '0'; aa++) ;
    for (bb = b[DB_serial]; *bb == '0'; bb++) ;
    return strcmp(aa, bb);
}

static int index_name_qual(char **a)
{
    return (a[0][0] == 'V');
}

static unsigned long index_name_hash(const OPENSSL_CSTRING *a)
{
    return OPENSSL_LH_strhash(a[DB_name]);
}

int index_name_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b)
{
    return strcmp(a[DB_name], b[DB_name]);
}

static IMPLEMENT_LHASH_HASH_FN(index_serial, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_COMP_FN(index_serial, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_HASH_FN(index_name, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_COMP_FN(index_name, OPENSSL_CSTRING)
#undef BSIZE
#define BSIZE 256
int parse_yesno(const char *str, int def)
{
    if (str) {
        switch (*str) {
        case 'f':              /* false */
        case 'F':              /* FALSE */
        case 'n':              /* no */
        case 'N':              /* NO */
        case '0':              /* 0 */
            return 0;
        case 't':              /* true */
        case 'T':              /* TRUE */
        case 'y':              /* yes */
        case 'Y':              /* YES */
        case '1':              /* 1 */
            return 1;
        }
    }
    return def;
}

/*
 * Read whole contents of a BIO into an allocated memory buffer and return
 * it.
 */

int bio_to_mem(unsigned char **out, int maxlen, BIO *in)
{
    BIO *mem;
    int len, ret;
    unsigned char tbuf[1024];

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL)
        return -1;
    for (;;) {
        if ((maxlen != -1) && maxlen < 1024)
            len = maxlen;
        else
            len = 1024;
        len = BIO_read(in, tbuf, len);
        if (len < 0) {
            BIO_free(mem);
            return -1;
        }
        if (len == 0)
            break;
        if (BIO_write(mem, tbuf, len) != len) {
            BIO_free(mem);
            return -1;
        }
        maxlen -= len;

        if (maxlen == 0)
            break;
    }
    ret = BIO_get_mem_data(mem, (char **)out);
    BIO_set_flags(mem, BIO_FLAGS_MEM_RDONLY);
    BIO_free(mem);
    return ret;
}

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
    int rv;
    char *stmp, *vtmp = NULL;
    stmp = OPENSSL_strdup(value);
    if (!stmp)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp) {
        *vtmp = 0;
        vtmp++;
    }
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
    OPENSSL_free(stmp);
    return rv;
}
/*-
 * next_protos_parse parses a comma separated list of strings into a string
 * in a format suitable for passing to SSL_CTX_set_next_protos_advertised.
 *   outlen: (output) set to the length of the resulting buffer on success.
 *   err: (maybe NULL) on failure, an error message line is written to this BIO.
 *   in: a NUL terminated string like "abc,def,ghi"
 *
 *   returns: a malloc'd buffer or NULL on failure.
 */
unsigned char *next_protos_parse(size_t *outlen, const char *in)
{
    size_t len;
    unsigned char *out;
    size_t i, start = 0;
    size_t skipped = 0;

    len = strlen(in);
    if (len == 0 || len >= 65535)
        return NULL;

    out = app_malloc(len + 1, "NPN buffer");
    for (i = 0; i <= len; ++i) {
        if (i == len || in[i] == ',') {
            /*
             * Zero-length ALPN elements are invalid on the wire, we could be
             * strict and reject the entire string, but just ignoring extra
             * commas seems harmless and more friendly.
             *
             * Every comma we skip in this way puts the input buffer another
             * byte ahead of the output buffer, so all stores into the output
             * buffer need to be decremented by the number commas skipped.
             */
            if (i == start) {
                ++start;
                ++skipped;
                continue;
            }
            if (i - start > 255) {
                OPENSSL_free(out);
                return NULL;
            }
            out[start-skipped] = (unsigned char)(i - start);
            start = i + 1;
        } else {
            out[i + 1 - skipped] = in[i];
        }
    }

    if (len <= skipped) {
        OPENSSL_free(out);
        return NULL;
    }

    *outlen = len + 1 - skipped;
    return out;
}

void print_cert_checks(BIO *bio, X509 *x,
                       const char *checkhost,
                       const char *checkemail, const char *checkip)
{
    if (x == NULL)
        return;
    if (checkhost) {
        BIO_printf(bio, "Hostname %s does%s match certificate\n",
                   checkhost,
                   X509_check_host(x, checkhost, 0, 0, NULL) == 1
                       ? "" : " NOT");
    }

    if (checkemail) {
        BIO_printf(bio, "Email %s does%s match certificate\n",
                   checkemail, X509_check_email(x, checkemail, 0, 0)
                   ? "" : " NOT");
    }

    if (checkip) {
        BIO_printf(bio, "IP %s does%s match certificate\n",
                   checkip, X509_check_ip_asc(x, checkip, 0) ? "" : " NOT");
    }
}

/* Get first http URL from a DIST_POINT structure */

static const char *get_dp_url(DIST_POINT *dp)
{
    GENERAL_NAMES *gens;
    GENERAL_NAME *gen;
    int i, gtype;
    ASN1_STRING *uri;
    if (!dp->distpoint || dp->distpoint->type != 0)
        return NULL;
    gens = dp->distpoint->name.fullname;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = GENERAL_NAME_get0_value(gen, &gtype);
        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
            const char *uptr = (const char *)ASN1_STRING_get0_data(uri);
            if (strncmp(uptr, "http://", 7) == 0)
                return uptr;
        }
    }
    return NULL;
}

/*
 * Centralized handling if input and output files with format specification
 * The format is meant to show what the input and output is supposed to be,
 * and is therefore a show of intent more than anything else.  However, it
 * does impact behavior on some platform, such as differentiating between
 * text and binary input/output on non-Unix platforms
 */
static int istext(int format)
{
    return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

BIO *dup_bio_in(int format)
{
    return BIO_new_fp(stdin,
                      BIO_NOCLOSE | (istext(format) ? BIO_FP_TEXT : 0));
}

static BIO_METHOD *prefix_method = NULL;

BIO *dup_bio_out(int format)
{
    BIO *b = BIO_new_fp(stdout,
                        BIO_NOCLOSE | (istext(format) ? BIO_FP_TEXT : 0));
    void *prefix = NULL;

    if (istext(format) && (prefix = getenv("HARNESS_OSSL_PREFIX")) != NULL) {
        b = BIO_push(BIO_new(prefix_method), b);
        BIO_ctrl(b, PREFIX_CTRL_SET_PREFIX, 0, prefix);
    }

    return b;
}


static const char *modestr(char mode, int format)
{
    OPENSSL_assert(mode == 'a' || mode == 'r' || mode == 'w');

    switch (mode) {
    case 'a':
        return istext(format) ? "a" : "ab";
    case 'r':
        return istext(format) ? "r" : "rb";
    case 'w':
        return istext(format) ? "w" : "wb";
    }
    /* The assert above should make sure we never reach this point */
    return NULL;
}

static const char *modeverb(char mode)
{
    switch (mode) {
    case 'a':
        return "appending";
    case 'r':
        return "reading";
    case 'w':
        return "writing";
    }
    return "(doing something)";
}

static BIO *bio_open_default_(const char *filename, char mode, int format,
                              int quiet)
{
    BIO *ret;

    if (filename == NULL || strcmp(filename, "-") == 0) {
        ret = mode == 'r' ? dup_bio_in(format) : dup_bio_out(format);
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        printf("Can't open %s, %s\n",
                   mode == 'r' ? "stdin" : "stdout", strerror(errno));
    } else {
        ret = BIO_new_file(filename, modestr(mode, format));
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        printf("Can't open %s for %s, %s\n",
                   filename, modeverb(mode), strerror(errno));
    }
    return NULL;
}

BIO *bio_open_default(const char *filename, char mode, int format)
{
    return bio_open_default_(filename, mode, format, 0);
}

