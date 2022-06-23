/* crypto/ui/ui_compat.c */
/* ====================================================================
 * Copyright (c) 2001-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <string.h>
#include "ui_compat.h"

int _ossl_old_des_read_pw_string(char *buf, int length, const char *prompt,
                                 int verify)
{
    return UI_UTIL_read_pw_string(buf, length, prompt, verify);
}

int _ossl_old_des_read_pw(char *buf, char *buff, int size, const char *prompt,
                          int verify)
{
    return UI_UTIL_read_pw(buf, buff, size, prompt, verify);
}
/* crypto/ui/ui_err.c */
/* ====================================================================
 * Copyright (c) 1999-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/*
 * NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
#include "err.h"
#include "ui.h"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

# define ERR_FUNC(func) ERR_PACK(ERR_LIB_UI,func,0)
# define ERR_REASON(reason) ERR_PACK(ERR_LIB_UI,0,reason)

static ERR_STRING_DATA UI_str_functs[] = {
    {ERR_FUNC(UI_F_GENERAL_ALLOCATE_BOOLEAN), "GENERAL_ALLOCATE_BOOLEAN"},
    {ERR_FUNC(UI_F_GENERAL_ALLOCATE_PROMPT), "GENERAL_ALLOCATE_PROMPT"},
    {ERR_FUNC(UI_F_GENERAL_ALLOCATE_STRING), "GENERAL_ALLOCATE_STRING"},
    {ERR_FUNC(UI_F_UI_CTRL), "UI_ctrl"},
    {ERR_FUNC(UI_F_UI_DUP_ERROR_STRING), "UI_dup_error_string"},
    {ERR_FUNC(UI_F_UI_DUP_INFO_STRING), "UI_dup_info_string"},
    {ERR_FUNC(UI_F_UI_DUP_INPUT_BOOLEAN), "UI_dup_input_boolean"},
    {ERR_FUNC(UI_F_UI_DUP_INPUT_STRING), "UI_dup_input_string"},
    {ERR_FUNC(UI_F_UI_DUP_VERIFY_STRING), "UI_dup_verify_string"},
    {ERR_FUNC(UI_F_UI_GET0_RESULT), "UI_get0_result"},
    {ERR_FUNC(UI_F_UI_NEW_METHOD), "UI_new_method"},
    {ERR_FUNC(UI_F_UI_SET_RESULT), "UI_set_result"},
    {0, NULL}
};

static ERR_STRING_DATA UI_str_reasons[] = {
    {ERR_REASON(UI_R_COMMON_OK_AND_CANCEL_CHARACTERS),
     "common ok and cancel characters"},
    {ERR_REASON(UI_R_INDEX_TOO_LARGE), "index too large"},
    {ERR_REASON(UI_R_INDEX_TOO_SMALL), "index too small"},
    {ERR_REASON(UI_R_NO_RESULT_BUFFER), "no result buffer"},
    {ERR_REASON(UI_R_RESULT_TOO_LARGE), "result too large"},
    {ERR_REASON(UI_R_RESULT_TOO_SMALL), "result too small"},
    {ERR_REASON(UI_R_UNKNOWN_CONTROL_COMMAND), "unknown control command"},
    {0, NULL}
};

#endif

void ERR_load_UI_strings(void)
{
#ifndef OPENSSL_NO_ERR

    if (ERR_func_error_string(UI_str_functs[0].error) == NULL) {
        ERR_load_strings(0, UI_str_functs);
        ERR_load_strings(0, UI_str_reasons);
    }
#endif
}
/* crypto/ui/ui_lib.c */
/*
 * Written by Richard Levitte (richard@levitte.org) for the OpenSSL project
 * 2001.
 */
/* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <string.h>
#include "cryptlib.h"
#include "e_os2.h"
#include "buffer.h"
// #include "ui.h"
// #include "err.h"
#include "ui_locl.h"

IMPLEMENT_STACK_OF(UI_STRING_ST)

static const UI_METHOD *default_UI_meth = NULL;

UI *UI_new(void)
{
    return (UI_new_method(NULL));
}

UI *UI_new_method(const UI_METHOD *method)
{
    UI *ret;

    ret = (UI *)OPENSSL_malloc(sizeof(UI));
    if (ret == NULL) {
        UIerr(UI_F_UI_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (method == NULL)
        ret->meth = UI_get_default_method();
    else
        ret->meth = method;

    ret->strings = NULL;
    ret->user_data = NULL;
    ret->flags = 0;
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_UI, ret, &ret->ex_data);
    return ret;
}

static void free_string(UI_STRING *uis)
{
    if (uis->flags & OUT_STRING_FREEABLE) {
        OPENSSL_free((char *)uis->out_string);
        switch (uis->type) {
        case UIT_BOOLEAN:
            OPENSSL_free((char *)uis->_.boolean_data.action_desc);
            OPENSSL_free((char *)uis->_.boolean_data.ok_chars);
            OPENSSL_free((char *)uis->_.boolean_data.cancel_chars);
            break;
        default:
            break;
        }
    }
    OPENSSL_free(uis);
}

void UI_free(UI *ui)
{
    if (ui == NULL)
        return;
    sk_UI_STRING_pop_free(ui->strings, free_string);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_UI, ui, &ui->ex_data);
    OPENSSL_free(ui);
}

static int allocate_string_stack(UI *ui)
{
    if (ui->strings == NULL) {
        ui->strings = sk_UI_STRING_new_null();
        if (ui->strings == NULL) {
            return -1;
        }
    }
    return 0;
}

static UI_STRING *general_allocate_prompt(UI *ui, const char *prompt,
                                          int prompt_freeable,
                                          enum UI_string_types type,
                                          int input_flags, char *result_buf)
{
    UI_STRING *ret = NULL;

    if (prompt == NULL) {
        UIerr(UI_F_GENERAL_ALLOCATE_PROMPT, ERR_R_PASSED_NULL_PARAMETER);
    } else if ((type == UIT_PROMPT || type == UIT_VERIFY
                || type == UIT_BOOLEAN) && result_buf == NULL) {
        UIerr(UI_F_GENERAL_ALLOCATE_PROMPT, UI_R_NO_RESULT_BUFFER);
    } else if ((ret = (UI_STRING *)OPENSSL_malloc(sizeof(UI_STRING)))) {
        ret->out_string = prompt;
        ret->flags = prompt_freeable ? OUT_STRING_FREEABLE : 0;
        ret->input_flags = input_flags;
        ret->type = type;
        ret->result_buf = result_buf;
    }
    return ret;
}

static int general_allocate_string(UI *ui, const char *prompt,
                                   int prompt_freeable,
                                   enum UI_string_types type, int input_flags,
                                   char *result_buf, int minsize, int maxsize,
                                   const char *test_buf)
{
    int ret = -1;
    UI_STRING *s = general_allocate_prompt(ui, prompt, prompt_freeable,
                                           type, input_flags, result_buf);

    if (s != NULL) {
        if (allocate_string_stack(ui) >= 0) {
            s->_.string_data.result_minsize = minsize;
            s->_.string_data.result_maxsize = maxsize;
            s->_.string_data.test_buf = test_buf;
            ret = sk_UI_STRING_push(ui->strings, s);
            /* sk_push() returns 0 on error.  Let's addapt that */
            if (ret <= 0)
                ret--;
        } else
            free_string(s);
    }
    return ret;
}

static int general_allocate_boolean(UI *ui,
                                    const char *prompt,
                                    const char *action_desc,
                                    const char *ok_chars,
                                    const char *cancel_chars,
                                    int prompt_freeable,
                                    enum UI_string_types type,
                                    int input_flags, char *result_buf)
{
    int ret = -1;
    UI_STRING *s;
    const char *p;

    if (ok_chars == NULL) {
        UIerr(UI_F_GENERAL_ALLOCATE_BOOLEAN, ERR_R_PASSED_NULL_PARAMETER);
    } else if (cancel_chars == NULL) {
        UIerr(UI_F_GENERAL_ALLOCATE_BOOLEAN, ERR_R_PASSED_NULL_PARAMETER);
    } else {
        for (p = ok_chars; *p != '\0'; p++) {
            if (strchr(cancel_chars, *p) != NULL) {
                UIerr(UI_F_GENERAL_ALLOCATE_BOOLEAN,
                      UI_R_COMMON_OK_AND_CANCEL_CHARACTERS);
            }
        }

        s = general_allocate_prompt(ui, prompt, prompt_freeable,
                                    type, input_flags, result_buf);

        if (s != NULL) {
            if (allocate_string_stack(ui) >= 0) {
                s->_.boolean_data.action_desc = action_desc;
                s->_.boolean_data.ok_chars = ok_chars;
                s->_.boolean_data.cancel_chars = cancel_chars;
                ret = sk_UI_STRING_push(ui->strings, s);
                /*
                 * sk_push() returns 0 on error. Let's addapt that
                 */
                if (ret <= 0)
                    ret--;
            } else
                free_string(s);
        }
    }
    return ret;
}

/*
 * Returns the index to the place in the stack or -1 for error.  Uses a
 * direct reference to the prompt.
 */
int UI_add_input_string(UI *ui, const char *prompt, int flags,
                        char *result_buf, int minsize, int maxsize)
{
    return general_allocate_string(ui, prompt, 0,
                                   UIT_PROMPT, flags, result_buf, minsize,
                                   maxsize, NULL);
}

/* Same as UI_add_input_string(), excepts it takes a copy of the prompt */
int UI_dup_input_string(UI *ui, const char *prompt, int flags,
                        char *result_buf, int minsize, int maxsize)
{
    char *prompt_copy = NULL;

    if (prompt != NULL) {
        prompt_copy = BUF_strdup(prompt);
        if (prompt_copy == NULL) {
            UIerr(UI_F_UI_DUP_INPUT_STRING, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    return general_allocate_string(ui, prompt_copy, 1,
                                   UIT_PROMPT, flags, result_buf, minsize,
                                   maxsize, NULL);
}

int UI_add_verify_string(UI *ui, const char *prompt, int flags,
                         char *result_buf, int minsize, int maxsize,
                         const char *test_buf)
{
    return general_allocate_string(ui, prompt, 0,
                                   UIT_VERIFY, flags, result_buf, minsize,
                                   maxsize, test_buf);
}

int UI_dup_verify_string(UI *ui, const char *prompt, int flags,
                         char *result_buf, int minsize, int maxsize,
                         const char *test_buf)
{
    char *prompt_copy = NULL;

    if (prompt != NULL) {
        prompt_copy = BUF_strdup(prompt);
        if (prompt_copy == NULL) {
            UIerr(UI_F_UI_DUP_VERIFY_STRING, ERR_R_MALLOC_FAILURE);
            return -1;
        }
    }

    return general_allocate_string(ui, prompt_copy, 1,
                                   UIT_VERIFY, flags, result_buf, minsize,
                                   maxsize, test_buf);
}

int UI_add_input_boolean(UI *ui, const char *prompt, const char *action_desc,
                         const char *ok_chars, const char *cancel_chars,
                         int flags, char *result_buf)
{
    return general_allocate_boolean(ui, prompt, action_desc,
                                    ok_chars, cancel_chars, 0, UIT_BOOLEAN,
                                    flags, result_buf);
}

int UI_dup_input_boolean(UI *ui, const char *prompt, const char *action_desc,
                         const char *ok_chars, const char *cancel_chars,
                         int flags, char *result_buf)
{
    char *prompt_copy = NULL;
    char *action_desc_copy = NULL;
    char *ok_chars_copy = NULL;
    char *cancel_chars_copy = NULL;

    if (prompt != NULL) {
        prompt_copy = BUF_strdup(prompt);
        if (prompt_copy == NULL) {
            UIerr(UI_F_UI_DUP_INPUT_BOOLEAN, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    if (action_desc != NULL) {
        action_desc_copy = BUF_strdup(action_desc);
        if (action_desc_copy == NULL) {
            UIerr(UI_F_UI_DUP_INPUT_BOOLEAN, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    if (ok_chars != NULL) {
        ok_chars_copy = BUF_strdup(ok_chars);
        if (ok_chars_copy == NULL) {
            UIerr(UI_F_UI_DUP_INPUT_BOOLEAN, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    if (cancel_chars != NULL) {
        cancel_chars_copy = BUF_strdup(cancel_chars);
        if (cancel_chars_copy == NULL) {
            UIerr(UI_F_UI_DUP_INPUT_BOOLEAN, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    return general_allocate_boolean(ui, prompt_copy, action_desc_copy,
                                    ok_chars_copy, cancel_chars_copy, 1,
                                    UIT_BOOLEAN, flags, result_buf);
 err:
    if (prompt_copy)
        OPENSSL_free(prompt_copy);
    if (action_desc_copy)
        OPENSSL_free(action_desc_copy);
    if (ok_chars_copy)
        OPENSSL_free(ok_chars_copy);
    if (cancel_chars_copy)
        OPENSSL_free(cancel_chars_copy);
    return -1;
}

int UI_add_info_string(UI *ui, const char *text)
{
    return general_allocate_string(ui, text, 0, UIT_INFO, 0, NULL, 0, 0,
                                   NULL);
}

int UI_dup_info_string(UI *ui, const char *text)
{
    char *text_copy = NULL;

    if (text != NULL) {
        text_copy = BUF_strdup(text);
        if (text_copy == NULL) {
            UIerr(UI_F_UI_DUP_INFO_STRING, ERR_R_MALLOC_FAILURE);
            return -1;
        }
    }

    return general_allocate_string(ui, text_copy, 1, UIT_INFO, 0, NULL,
                                   0, 0, NULL);
}

int UI_add_error_string(UI *ui, const char *text)
{
    return general_allocate_string(ui, text, 0, UIT_ERROR, 0, NULL, 0, 0,
                                   NULL);
}

int UI_dup_error_string(UI *ui, const char *text)
{
    char *text_copy = NULL;

    if (text != NULL) {
        text_copy = BUF_strdup(text);
        if (text_copy == NULL) {
            UIerr(UI_F_UI_DUP_ERROR_STRING, ERR_R_MALLOC_FAILURE);
            return -1;
        }
    }
    return general_allocate_string(ui, text_copy, 1, UIT_ERROR, 0, NULL,
                                   0, 0, NULL);
}

char *UI_construct_prompt(UI *ui, const char *object_desc,
                          const char *object_name)
{
    char *prompt = NULL;

    if (ui->meth->ui_construct_prompt != NULL)
        prompt = ui->meth->ui_construct_prompt(ui, object_desc, object_name);
    else {
        char prompt1[] = "Enter ";
        char prompt2[] = " for ";
        char prompt3[] = ":";
        int len = 0;

        if (object_desc == NULL)
            return NULL;
        len = sizeof(prompt1) - 1 + strlen(object_desc);
        if (object_name != NULL)
            len += sizeof(prompt2) - 1 + strlen(object_name);
        len += sizeof(prompt3) - 1;

        prompt = (char *)OPENSSL_malloc(len + 1);
        if (prompt == NULL)
            return NULL;
        BUF_strlcpy(prompt, prompt1, len + 1);
        BUF_strlcat(prompt, object_desc, len + 1);
        if (object_name != NULL) {
            BUF_strlcat(prompt, prompt2, len + 1);
            BUF_strlcat(prompt, object_name, len + 1);
        }
        BUF_strlcat(prompt, prompt3, len + 1);
    }
    return prompt;
}

void *UI_add_user_data(UI *ui, void *user_data)
{
    void *old_data = ui->user_data;
    ui->user_data = user_data;
    return old_data;
}

void *UI_get0_user_data(UI *ui)
{
    return ui->user_data;
}

const char *UI_get0_result(UI *ui, int i)
{
    if (i < 0) {
        UIerr(UI_F_UI_GET0_RESULT, UI_R_INDEX_TOO_SMALL);
        return NULL;
    }
    if (i >= sk_UI_STRING_num(ui->strings)) {
        UIerr(UI_F_UI_GET0_RESULT, UI_R_INDEX_TOO_LARGE);
        return NULL;
    }
    return UI_get0_result_string(sk_UI_STRING_value(ui->strings, i));
}

static int print_error(const char *str, size_t len, UI *ui)
{
    UI_STRING uis;

    memset(&uis, 0, sizeof(uis));
    uis.type = UIT_ERROR;
    uis.out_string = str;

    if (ui->meth->ui_write_string != NULL
        && ui->meth->ui_write_string(ui, &uis) <= 0)
        return -1;
    return 0;
}

int UI_process(UI *ui)
{
    int i, ok = 0;

    if (ui->meth->ui_open_session != NULL
        && ui->meth->ui_open_session(ui) <= 0) {
        ok = -1;
        goto err;
    }

    if (ui->flags & UI_FLAG_PRINT_ERRORS)
        ERR_print_errors_cb((int (*)(const char *, size_t, void *))
                            print_error, (void *)ui);

    for (i = 0; i < sk_UI_STRING_num(ui->strings); i++) {
        if (ui->meth->ui_write_string != NULL
            && (ui->meth->ui_write_string(ui,
                                          sk_UI_STRING_value(ui->strings, i))
                <= 0))
        {
            ok = -1;
            goto err;
        }
    }

    if (ui->meth->ui_flush != NULL)
        switch (ui->meth->ui_flush(ui)) {
        case -1:               /* Interrupt/Cancel/something... */
            ok = -2;
            goto err;
        case 0:                /* Errors */
            ok = -1;
            goto err;
        default:               /* Success */
            ok = 0;
            break;
        }

    for (i = 0; i < sk_UI_STRING_num(ui->strings); i++) {
        if (ui->meth->ui_read_string != NULL) {
            switch (ui->meth->ui_read_string(ui,
                                             sk_UI_STRING_value(ui->strings,
                                                                i))) {
            case -1:           /* Interrupt/Cancel/something... */
                ok = -2;
                goto err;
            case 0:            /* Errors */
                ok = -1;
                goto err;
            default:           /* Success */
                ok = 0;
                break;
            }
        }
    }

 err:
    if (ui->meth->ui_close_session != NULL
        && ui->meth->ui_close_session(ui) <= 0)
        return -1;
    return ok;
}

int UI_ctrl(UI *ui, int cmd, long i, void *p, void (*f) (void))
{
    if (ui == NULL) {
        UIerr(UI_F_UI_CTRL, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }
    switch (cmd) {
    case UI_CTRL_PRINT_ERRORS:
        {
            int save_flag = ! !(ui->flags & UI_FLAG_PRINT_ERRORS);
            if (i)
                ui->flags |= UI_FLAG_PRINT_ERRORS;
            else
                ui->flags &= ~UI_FLAG_PRINT_ERRORS;
            return save_flag;
        }
    case UI_CTRL_IS_REDOABLE:
        return ! !(ui->flags & UI_FLAG_REDOABLE);
    default:
        break;
    }
    UIerr(UI_F_UI_CTRL, UI_R_UNKNOWN_CONTROL_COMMAND);
    return -1;
}

int UI_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                        CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_UI, argl, argp,
                                   new_func, dup_func, free_func);
}

int UI_set_ex_data(UI *r, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&r->ex_data, idx, arg));
}

void *UI_get_ex_data(UI *r, int idx)
{
    return (CRYPTO_get_ex_data(&r->ex_data, idx));
}

void UI_set_default_method(const UI_METHOD *meth)
{
    default_UI_meth = meth;
}

const UI_METHOD *UI_get_default_method(void)
{
    if (default_UI_meth == NULL) {
        default_UI_meth = UI_OpenSSL();
    }
    return default_UI_meth;
}

const UI_METHOD *UI_get_method(UI *ui)
{
    return ui->meth;
}

const UI_METHOD *UI_set_method(UI *ui, const UI_METHOD *meth)
{
    ui->meth = meth;
    return ui->meth;
}

UI_METHOD *UI_create_method(char *name)
{
    UI_METHOD *ui_method = (UI_METHOD *)OPENSSL_malloc(sizeof(UI_METHOD));

    if (ui_method) {
        memset(ui_method, 0, sizeof(*ui_method));
        ui_method->name = BUF_strdup(name);
    }
    return ui_method;
}

/*
 * BIG FSCKING WARNING!!!! If you use this on a statically allocated method
 * (that is, it hasn't been allocated using UI_create_method(), you deserve
 * anything Murphy can throw at you and more! You have been warned.
 */
void UI_destroy_method(UI_METHOD *ui_method)
{
    OPENSSL_free(ui_method->name);
    ui_method->name = NULL;
    OPENSSL_free(ui_method);
}

int UI_method_set_opener(UI_METHOD *method, int (*opener) (UI *ui))
{
    if (method != NULL) {
        method->ui_open_session = opener;
        return 0;
    }
    return -1;
}

int UI_method_set_writer(UI_METHOD *method,
                         int (*writer) (UI *ui, UI_STRING *uis))
{
    if (method != NULL) {
        method->ui_write_string = writer;
        return 0;
    }
    return -1;
}

int UI_method_set_flusher(UI_METHOD *method, int (*flusher) (UI *ui))
{
    if (method != NULL) {
        method->ui_flush = flusher;
        return 0;
    }
    return -1;
}

int UI_method_set_reader(UI_METHOD *method,
                         int (*reader) (UI *ui, UI_STRING *uis))
{
    if (method != NULL) {
        method->ui_read_string = reader;
        return 0;
    }
    return -1;
}

int UI_method_set_closer(UI_METHOD *method, int (*closer) (UI *ui))
{
    if (method != NULL) {
        method->ui_close_session = closer;
        return 0;
    }
    return -1;
}

int UI_method_set_prompt_constructor(UI_METHOD *method,
                                     char *(*prompt_constructor) (UI *ui,
                                                                  const char
                                                                  *object_desc,
                                                                  const char
                                                                  *object_name))
{
    if (method != NULL) {
        method->ui_construct_prompt = prompt_constructor;
        return 0;
    }
    return -1;
}

int (*UI_method_get_opener(UI_METHOD *method)) (UI *)
{
    if (method != NULL)
        return method->ui_open_session;
    return NULL;
}

int (*UI_method_get_writer(UI_METHOD *method)) (UI *, UI_STRING *)
{
    if (method != NULL)
        return method->ui_write_string;
    return NULL;
}

int (*UI_method_get_flusher(UI_METHOD *method)) (UI *)
{
    if (method != NULL)
        return method->ui_flush;
    return NULL;
}

int (*UI_method_get_reader(UI_METHOD *method)) (UI *, UI_STRING *)
{
    if (method != NULL)
        return method->ui_read_string;
    return NULL;
}

int (*UI_method_get_closer(UI_METHOD *method)) (UI *)
{
    if (method != NULL)
        return method->ui_close_session;
    return NULL;
}

char *(*UI_method_get_prompt_constructor(UI_METHOD *method)) (UI *,
                                                              const char *,
                                                              const char *)
{
    if (method != NULL)
        return method->ui_construct_prompt;
    return NULL;
}

enum UI_string_types UI_get_string_type(UI_STRING *uis)
{
    if (!uis)
        return UIT_NONE;
    return uis->type;
}

int UI_get_input_flags(UI_STRING *uis)
{
    if (!uis)
        return 0;
    return uis->input_flags;
}

const char *UI_get0_output_string(UI_STRING *uis)
{
    if (!uis)
        return NULL;
    return uis->out_string;
}

const char *UI_get0_action_string(UI_STRING *uis)
{
    if (!uis)
        return NULL;
    switch (uis->type) {
    case UIT_BOOLEAN:
        return uis->_.boolean_data.action_desc;
    default:
        return NULL;
    }
}

const char *UI_get0_result_string(UI_STRING *uis)
{
    if (!uis)
        return NULL;
    switch (uis->type) {
    case UIT_PROMPT:
    case UIT_VERIFY:
        return uis->result_buf;
    default:
        return NULL;
    }
}

const char *UI_get0_test_string(UI_STRING *uis)
{
    if (!uis)
        return NULL;
    switch (uis->type) {
    case UIT_VERIFY:
        return uis->_.string_data.test_buf;
    default:
        return NULL;
    }
}

int UI_get_result_minsize(UI_STRING *uis)
{
    if (!uis)
        return -1;
    switch (uis->type) {
    case UIT_PROMPT:
    case UIT_VERIFY:
        return uis->_.string_data.result_minsize;
    default:
        return -1;
    }
}

int UI_get_result_maxsize(UI_STRING *uis)
{
    if (!uis)
        return -1;
    switch (uis->type) {
    case UIT_PROMPT:
    case UIT_VERIFY:
        return uis->_.string_data.result_maxsize;
    default:
        return -1;
    }
}

int UI_set_result(UI *ui, UI_STRING *uis, const char *result)
{
    int l = strlen(result);

    ui->flags &= ~UI_FLAG_REDOABLE;

    if (!uis)
        return -1;
    switch (uis->type) {
    case UIT_PROMPT:
    case UIT_VERIFY:
        {
            char number1[DECIMAL_SIZE(uis->_.string_data.result_minsize) + 1];
            char number2[DECIMAL_SIZE(uis->_.string_data.result_maxsize) + 1];

            BIO_snprintf(number1, sizeof(number1), "%d",
                         uis->_.string_data.result_minsize);
            BIO_snprintf(number2, sizeof(number2), "%d",
                         uis->_.string_data.result_maxsize);

            if (l < uis->_.string_data.result_minsize) {
                ui->flags |= UI_FLAG_REDOABLE;
                UIerr(UI_F_UI_SET_RESULT, UI_R_RESULT_TOO_SMALL);
                ERR_add_error_data(5, "You must type in ",
                                   number1, " to ", number2, " characters");
                return -1;
            }
            if (l > uis->_.string_data.result_maxsize) {
                ui->flags |= UI_FLAG_REDOABLE;
                UIerr(UI_F_UI_SET_RESULT, UI_R_RESULT_TOO_LARGE);
                ERR_add_error_data(5, "You must type in ",
                                   number1, " to ", number2, " characters");
                return -1;
            }
        }

        if (!uis->result_buf) {
            UIerr(UI_F_UI_SET_RESULT, UI_R_NO_RESULT_BUFFER);
            return -1;
        }

        BUF_strlcpy(uis->result_buf, result,
                    uis->_.string_data.result_maxsize + 1);
        break;
    case UIT_BOOLEAN:
        {
            const char *p;

            if (!uis->result_buf) {
                UIerr(UI_F_UI_SET_RESULT, UI_R_NO_RESULT_BUFFER);
                return -1;
            }

            uis->result_buf[0] = '\0';
            for (p = result; *p; p++) {
                if (strchr(uis->_.boolean_data.ok_chars, *p)) {
                    uis->result_buf[0] = uis->_.boolean_data.ok_chars[0];
                    break;
                }
                if (strchr(uis->_.boolean_data.cancel_chars, *p)) {
                    uis->result_buf[0] = uis->_.boolean_data.cancel_chars[0];
                    break;
                }
            }
        }
    default:
        break;
    }
    return 0;
}
/* crypto/ui/ui_openssl.c */
/*
 * Written by Richard Levitte (richard@levitte.org) and others for the
 * OpenSSL project 2001.
 */
/* ====================================================================
 * Copyright (c) 2001-2018 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/*-
 * The lowest level part of this file was previously in crypto/des/read_pwd.c,
 * Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

// #include "e_os2.h"

/*
 * need for #define _POSIX_C_SOURCE arises whenever you pass -ansi to gcc
 * [maybe others?], because it masks interfaces not discussed in standard,
 * sigaction and fileno included. -pedantic would be more appropriate for the
 * intended purposes, but we can't prevent users from adding -ansi.
 */
#if defined(OPENSSL_SYSNAME_VXWORKS)
# include <sys/types.h>
#endif

#if !defined(_POSIX_C_SOURCE) && defined(OPENSSL_SYS_VMS)
# ifndef _POSIX_C_SOURCE
#  define _POSIX_C_SOURCE 2
# endif
#endif
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#if !defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_VMS)
# ifdef OPENSSL_UNISTD
#  include OPENSSL_UNISTD
# else
#  include <unistd.h>
# endif
/*
 * If unistd.h defines _POSIX_VERSION, we conclude that we are on a POSIX
 * system and have sigaction and termios.
 */
# if defined(_POSIX_VERSION)

#  define SIGACTION
#  if !defined(TERMIOS) && !defined(TERMIO) && !defined(SGTTY)
#   define TERMIOS
#  endif

# endif
#endif

#ifdef WIN16TTY
# undef OPENSSL_SYS_WIN16
# undef WIN16
# undef _WINDOWS
# include <graph.h>
#endif

/* 06-Apr-92 Luke Brennan    Support for VMS */
// #include "ui_locl.h"
// #include "cryptlib.h"

#ifdef OPENSSL_SYS_VMS          /* prototypes for sys$whatever */
# include <starlet.h>
# ifdef __DECC
#  pragma message disable DOLLARID
# endif
#endif

#ifdef WIN_CONSOLE_BUG
# include <windows.h>
# ifndef OPENSSL_SYS_WINCE
#  include <wincon.h>
# endif
#endif

/*
 * There are 5 types of terminal interface supported, TERMIO, TERMIOS, VMS,
 * MSDOS and SGTTY.
 *
 * If someone defines one of the macros TERMIO, TERMIOS or SGTTY, it will
 * remain respected.  Otherwise, we default to TERMIOS except for a few
 * systems that require something different.
 *
 * Note: we do not use SGTTY unless it's defined by the configuration.  We
 * may eventually opt to remove it's use entirely.
 */

#if !defined(TERMIOS) && !defined(TERMIO) && !defined(SGTTY)

# if defined(_LIBC)
#  undef  TERMIOS
#  define TERMIO
#  undef  SGTTY
/*
 * We know that VMS, MSDOS, VXWORKS, NETWARE use entirely other mechanisms.
 * MAC_OS_GUSI_SOURCE should probably go away, but that needs to be confirmed.
 */
# elif !defined(OPENSSL_SYS_VMS) \
	&& !defined(OPENSSL_SYS_MSDOS) \
	&& !defined(OPENSSL_SYS_MACINTOSH_CLASSIC) \
	&& !defined(MAC_OS_GUSI_SOURCE)	\
	&& !defined(OPENSSL_SYS_VXWORKS) \
	&& !defined(OPENSSL_SYS_NETWARE)
#  define TERMIOS
#  undef  TERMIO
#  undef  SGTTY
# endif

#endif

#ifdef TERMIOS
# include <termios.h>
# define TTY_STRUCT             struct termios
# define TTY_FLAGS              c_lflag
# define TTY_get(tty,data)      tcgetattr(tty,data)
# define TTY_set(tty,data)      tcsetattr(tty,TCSANOW,data)
#endif

#ifdef TERMIO
# include <termio.h>
# define TTY_STRUCT             struct termio
# define TTY_FLAGS              c_lflag
# define TTY_get(tty,data)      ioctl(tty,TCGETA,data)
# define TTY_set(tty,data)      ioctl(tty,TCSETA,data)
#endif

#ifdef SGTTY
# include <sgtty.h>
# define TTY_STRUCT             struct sgttyb
# define TTY_FLAGS              sg_flags
# define TTY_get(tty,data)      ioctl(tty,TIOCGETP,data)
# define TTY_set(tty,data)      ioctl(tty,TIOCSETP,data)
#endif

#if !defined(_LIBC) && !defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_VMS) && !defined(OPENSSL_SYS_MACINTOSH_CLASSIC) && !defined(OPENSSL_SYS_SUNOS)
# include <sys/ioctl.h>
#endif

#ifdef OPENSSL_SYS_MSDOS
# include <conio.h>
#endif

#ifdef OPENSSL_SYS_VMS
# include <ssdef.h>
# include <iodef.h>
# include <ttdef.h>
# include <descrip.h>
struct IOSB {
    short iosb$w_value;
    short iosb$w_count;
    long iosb$l_info;
};
#endif

#ifdef OPENSSL_SYS_SUNOS
typedef int sig_atomic_t;
#endif

#if defined(OPENSSL_SYS_MACINTOSH_CLASSIC) || defined(MAC_OS_GUSI_SOURCE) || defined(OPENSSL_SYS_NETWARE)
/*
 * This one needs work. As a matter of fact the code is unoperational
 * and this is only a trick to get it compiled.
 *                                      <appro@fy.chalmers.se>
 */
# define TTY_STRUCT int
#endif

#ifndef NX509_SIG
# define NX509_SIG 32
#endif

/* Define globals.  They are protected by a lock */
#ifdef SIGACTION
static struct sigaction savsig[NX509_SIG];
#else
static void (*savsig[NX509_SIG]) (int);
#endif

#ifdef OPENSSL_SYS_VMS
static struct IOSB iosb;
static $DESCRIPTOR(terminal, "TT");
static long tty_orig[3], tty_new[3]; /* XXX Is there any guarantee that this
                                      * will always suffice for the actual
                                      * structures? */
static long status;
static unsigned short channel = 0;
#else
# if !defined(OPENSSL_SYS_MSDOS) || defined(__DJGPP__)
static TTY_STRUCT tty_orig, tty_new;
# endif
#endif
static FILE *tty_in, *tty_out;
static int is_a_tty;

/* Declare static functions */
#if !defined(OPENSSL_SYS_WIN16) && !defined(OPENSSL_SYS_WINCE)
static int read_till_nl(FILE *);
static void recsig(int);
static void pushsig(void);
static void popsig(void);
#endif
#if defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_WIN16)
static int noecho_fgets(char *buf, int size, FILE *tty);
#endif
static int read_string_inner(UI *ui, UI_STRING *uis, int echo, int strip_nl);

static int read_string(UI *ui, UI_STRING *uis);
static int write_string(UI *ui, UI_STRING *uis);

static int open_console(UI *ui);
static int echo_console(UI *ui);
static int noecho_console(UI *ui);
static int close_console(UI *ui);

static UI_METHOD ui_openssl = {
    "OpenSSL default user interface",
    open_console,
    write_string,
    NULL,                       /* No flusher is needed for command lines */
    read_string,
    close_console,
    NULL
};

/* The method with all the built-in thingies */
UI_METHOD *UI_OpenSSL(void)
{
    return &ui_openssl;
}

/*
 * The following function makes sure that info and error strings are printed
 * before any prompt.
 */
static int write_string(UI *ui, UI_STRING *uis)
{
    switch (UI_get_string_type(uis)) {
    case UIT_ERROR:
    case UIT_INFO:
        fputs(UI_get0_output_string(uis), tty_out);
        fflush(tty_out);
        break;
    default:
        break;
    }
    return 1;
}

static int read_string(UI *ui, UI_STRING *uis)
{
    int ok = 0;

    switch (UI_get_string_type(uis)) {
    case UIT_BOOLEAN:
        fputs(UI_get0_output_string(uis), tty_out);
        fputs(UI_get0_action_string(uis), tty_out);
        fflush(tty_out);
        return read_string_inner(ui, uis,
                                 UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO,
                                 0);
    case UIT_PROMPT:
        fputs(UI_get0_output_string(uis), tty_out);
        fflush(tty_out);
        return read_string_inner(ui, uis,
                                 UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO,
                                 1);
    case UIT_VERIFY:
        fprintf(tty_out, "Verifying - %s", UI_get0_output_string(uis));
        fflush(tty_out);
        if ((ok = read_string_inner(ui, uis,
                                    UI_get_input_flags(uis) &
                                    UI_INPUT_FLAG_ECHO, 1)) <= 0)
            return ok;
        if (strcmp(UI_get0_result_string(uis), UI_get0_test_string(uis)) != 0) {
            fprintf(tty_out, "Verify failure\n");
            fflush(tty_out);
            return 0;
        }
        break;
    default:
        break;
    }
    return 1;
}

#if !defined(OPENSSL_SYS_WIN16) && !defined(OPENSSL_SYS_WINCE)
/* Internal functions to read a string without echoing */
static int read_till_nl(FILE *in)
{
# define SIZE 4
    char buf[SIZE + 1];

    do {
        if (!fgets(buf, SIZE, in))
            return 0;
    } while (strchr(buf, '\n') == NULL);
    return 1;
}

static volatile sig_atomic_t intr_signal;
#endif

static int read_string_inner(UI *ui, UI_STRING *uis, int echo, int strip_nl)
{
    static int ps;
    int ok;
    char result[BUFSIZ];
    int maxsize = BUFSIZ - 1;
#if !defined(OPENSSL_SYS_WIN16) && !defined(OPENSSL_SYS_WINCE)
    char *p;

    intr_signal = 0;
    ok = 0;
    ps = 0;

    pushsig();
    ps = 1;

    if (!echo && !noecho_console(ui))
        goto error;
    ps = 2;

    result[0] = '\0';
# ifdef OPENSSL_SYS_MSDOS
    if (!echo) {
        noecho_fgets(result, maxsize, tty_in);
        p = result;             /* FIXME: noecho_fgets doesn't return errors */
    } else
        p = fgets(result, maxsize, tty_in);
# else
    p = fgets(result, maxsize, tty_in);
# endif
    if (p == NULL)
        goto error;
    if (feof(tty_in))
        goto error;
    if (ferror(tty_in))
        goto error;
    if ((p = (char *)strchr(result, '\n')) != NULL) {
        if (strip_nl)
            *p = '\0';
    } else if (!read_till_nl(tty_in))
        goto error;
    if (UI_set_result(ui, uis, result) >= 0)
        ok = 1;

 error:
    if (intr_signal == SIGINT)
        ok = -1;
    if (!echo)
        fprintf(tty_out, "\n");
    if (ps >= 2 && !echo && !echo_console(ui))
        ok = 0;

    if (ps >= 1)
        popsig();
#else
    ok = 1;
#endif

    OPENSSL_cleanse(result, BUFSIZ);
    return ok;
}

/* Internal functions to open, handle and close a channel to the console.  */
static int open_console(UI *ui)
{
    CRYPTO_w_lock(CRYPTO_LOCK_UI);
    is_a_tty = 1;

#if defined(OPENSSL_SYS_MACINTOSH_CLASSIC) || defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_NETWARE) || defined(OPENSSL_SYS_BEOS)
    tty_in = stdin;
    tty_out = stderr;
#else
# ifdef OPENSSL_SYS_MSDOS
#  define DEV_TTY "con"
# else
#  define DEV_TTY "/dev/tty"
# endif
    if ((tty_in = fopen(DEV_TTY, "r")) == NULL)
        tty_in = stdin;
    if ((tty_out = fopen(DEV_TTY, "w")) == NULL)
        tty_out = stderr;
#endif

#if defined(TTY_get) && !defined(OPENSSL_SYS_VMS)
    if (TTY_get(fileno(tty_in), &tty_orig) == -1) {
# ifdef ENOTTY
        if (errno == ENOTTY)
            is_a_tty = 0;
        else
# endif
# ifdef EINVAL
            /*
             * Ariel Glenn ariel@columbia.edu reports that solaris can return
             * EINVAL instead.  This should be ok
             */
        if (errno == EINVAL)
            is_a_tty = 0;
        else
# endif
# ifdef ENXIO
            /*
             * Solaris can return ENXIO.
             * This should be ok
             */
        if (errno == ENXIO)
            is_a_tty = 0;
        else
# endif
# ifdef EIO
            /*
             * Linux can return EIO.
             * This should be ok
             */
        if (errno == EIO)
            is_a_tty = 0;
        else
# endif
# ifdef ENODEV
            /*
             * MacOS X returns ENODEV (Operation not supported by device),
             * which seems appropriate.
             */
        if (errno == ENODEV)
            is_a_tty = 0;
        else
# endif
            return 0;
    }
#endif
#ifdef OPENSSL_SYS_VMS
    status = sys$assign(&terminal, &channel, 0, 0);

    /* if there isn't a TT device, something is very wrong */
    if (status != SS$_NORMAL)
        return 0;

    status = sys$qiow(0, channel, IO$_SENSEMODE, &iosb, 0, 0, tty_orig, 12,
                      0, 0, 0, 0);

    /* If IO$_SENSEMODE doesn't work, this is not a terminal device */
    if ((status != SS$_NORMAL) || (iosb.iosb$w_value != SS$_NORMAL))
        is_a_tty = 0;
#endif
    return 1;
}

static int noecho_console(UI *ui)
{
#ifdef TTY_FLAGS
    memcpy(&(tty_new), &(tty_orig), sizeof(tty_orig));
    tty_new.TTY_FLAGS &= ~ECHO;
#endif

#if defined(TTY_set) && !defined(OPENSSL_SYS_VMS)
    if (is_a_tty && (TTY_set(fileno(tty_in), &tty_new) == -1))
        return 0;
#endif
#ifdef OPENSSL_SYS_VMS
    if (is_a_tty) {
        tty_new[0] = tty_orig[0];
        tty_new[1] = tty_orig[1] | TT$M_NOECHO;
        tty_new[2] = tty_orig[2];
        status = sys$qiow(0, channel, IO$_SETMODE, &iosb, 0, 0, tty_new, 12,
                          0, 0, 0, 0);
        if ((status != SS$_NORMAL) || (iosb.iosb$w_value != SS$_NORMAL))
            return 0;
    }
#endif
    return 1;
}

static int echo_console(UI *ui)
{
#if defined(TTY_set) && !defined(OPENSSL_SYS_VMS)
    memcpy(&(tty_new), &(tty_orig), sizeof(tty_orig));
    if (is_a_tty && (TTY_set(fileno(tty_in), &tty_new) == -1))
        return 0;
#endif
#ifdef OPENSSL_SYS_VMS
    if (is_a_tty) {
        tty_new[0] = tty_orig[0];
        tty_new[1] = tty_orig[1];
        tty_new[2] = tty_orig[2];
        status = sys$qiow(0, channel, IO$_SETMODE, &iosb, 0, 0, tty_new, 12,
                          0, 0, 0, 0);
        if ((status != SS$_NORMAL) || (iosb.iosb$w_value != SS$_NORMAL))
            return 0;
    }
#endif
    return 1;
}

static int close_console(UI *ui)
{
    if (tty_in != stdin)
        fclose(tty_in);
    if (tty_out != stderr)
        fclose(tty_out);
#ifdef OPENSSL_SYS_VMS
    status = sys$dassgn(channel);
    if (status != SS$_NORMAL)
        return 0;
#endif
    CRYPTO_w_unlock(CRYPTO_LOCK_UI);

    return 1;
}

#if !defined(OPENSSL_SYS_WIN16) && !defined(OPENSSL_SYS_WINCE)
/* Internal functions to handle signals and act on them */
static void pushsig(void)
{
# ifndef OPENSSL_SYS_WIN32
    int i;
# endif
# ifdef SIGACTION
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = recsig;
# endif

# ifdef OPENSSL_SYS_WIN32
    savsig[SIGABRT] = signal(SIGABRT, recsig);
    savsig[SIGFPE] = signal(SIGFPE, recsig);
    savsig[SIGILL] = signal(SIGILL, recsig);
    savsig[SIGINT] = signal(SIGINT, recsig);
    savsig[SIGSEGV] = signal(SIGSEGV, recsig);
    savsig[SIGTERM] = signal(SIGTERM, recsig);
# else
    for (i = 1; i < NX509_SIG; i++) {
#  ifdef SIGUSR1
        if (i == SIGUSR1)
            continue;
#  endif
#  ifdef SIGUSR2
        if (i == SIGUSR2)
            continue;
#  endif
#  ifdef SIGKILL
        if (i == SIGKILL)       /* We can't make any action on that. */
            continue;
#  endif
#  ifdef SIGACTION
        sigaction(i, &sa, &savsig[i]);
#  else
        savsig[i] = signal(i, recsig);
#  endif
    }
# endif

# ifdef SIGWINCH
    signal(SIGWINCH, SIG_DFL);
# endif
}

static void popsig(void)
{
# ifdef OPENSSL_SYS_WIN32
    signal(SIGABRT, savsig[SIGABRT]);
    signal(SIGFPE, savsig[SIGFPE]);
    signal(SIGILL, savsig[SIGILL]);
    signal(SIGINT, savsig[SIGINT]);
    signal(SIGSEGV, savsig[SIGSEGV]);
    signal(SIGTERM, savsig[SIGTERM]);
# else
    int i;
    for (i = 1; i < NX509_SIG; i++) {
#  ifdef SIGUSR1
        if (i == SIGUSR1)
            continue;
#  endif
#  ifdef SIGUSR2
        if (i == SIGUSR2)
            continue;
#  endif
#  ifdef SIGACTION
        sigaction(i, &savsig[i], NULL);
#  else
        signal(i, savsig[i]);
#  endif
    }
# endif
}

static void recsig(int i)
{
    intr_signal = i;
}
#endif

/* Internal functions specific for Windows */
#if defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_WIN16) && !defined(OPENSSL_SYS_WINCE)
static int noecho_fgets(char *buf, int size, FILE *tty)
{
    int i;
    char *p;

    p = buf;
    for (;;) {
        if (size == 0) {
            *p = '\0';
            break;
        }
        size--;
# ifdef WIN16TTY
        i = _inchar();
# elif defined(_WIN32)
        i = _getch();
# else
        i = getch();
# endif
        if (i == '\r')
            i = '\n';
        *(p++) = i;
        if (i == '\n') {
            *p = '\0';
            break;
        }
    }
# ifdef WIN_CONSOLE_BUG
    /*
     * Win95 has several evil console bugs: one of these is that the last
     * character read using getch() is passed to the next read: this is
     * usually a CR so this can be trouble. No STDIO fix seems to work but
     * flushing the console appears to do the trick.
     */
    {
        HANDLE inh;
        inh = GetStdHandle(STD_INPUT_HANDLE);
        FlushConsoleInputBuffer(inh);
    }
# endif
    return (strlen(buf));
}
#endif
/* crypto/ui/ui_util.c */
/* ====================================================================
 * Copyright (c) 2001-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <string.h>
// #include "ui_locl.h"

int UI_UTIL_read_pw_string(char *buf, int length, const char *prompt,
                           int verify)
{
    char buff[BUFSIZ];
    int ret;

    ret =
        UI_UTIL_read_pw(buf, buff, (length > BUFSIZ) ? BUFSIZ : length,
                        prompt, verify);
    OPENSSL_cleanse(buff, BUFSIZ);
    return (ret);
}

int UI_UTIL_read_pw(char *buf, char *buff, int size, const char *prompt,
                    int verify)
{
    int ok = 0;
    UI *ui;

    if (size < 1)
        return -1;

    ui = UI_new();
    if (ui) {
        ok = UI_add_input_string(ui, prompt, 0, buf, 0, size - 1);
        if (ok >= 0 && verify)
            ok = UI_add_verify_string(ui, prompt, 0, buff, 0, size - 1, buf);
        if (ok >= 0)
            ok = UI_process(ui);
        UI_free(ui);
    }
    if (ok > 0)
        ok = 0;
    return (ok);
}
