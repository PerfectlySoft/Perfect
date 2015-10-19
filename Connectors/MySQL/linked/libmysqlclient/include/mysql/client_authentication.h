#ifndef CLIENT_AUTHENTICATION_H
#define CLIENT_AUTHENTICATION_H
#include <my_global.h>
#include "mysql.h"
#include "mysql/client_plugin.h"

C_MODE_START
int sha256_password_auth_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql);
int sha256_password_init(char *, size_t, int, va_list);
int sha256_password_deinit(void);
C_MODE_END

#endif

