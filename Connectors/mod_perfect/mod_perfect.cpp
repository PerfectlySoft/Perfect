//
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//


#include "mod_perfect.h"
#include <string>
#ifndef WIN32
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/un.h>
#define LP_OPEN_FLAGS (O_RDONLY)
#define CACHE_HOSTS 1
#define SOCKET int
#define CLOSE_SOCKET(S) close(S)
#else
#include <winsock2.h>
#include <stdint.h>
#define LP_OPEN_FLAGS (O_RDONLY | O_BINARY)
#define CACHE_HOSTS 0
#define usleep(N) Sleep((N)/1000)
#define CLOSE_SOCKET(S) CloseHandle((HANDLE)S)
#endif
#include <sys/stat.h>
#include <http_request.h>
#include <http_log.h>
#include <apr_strings.h>
#include <util_script.h>
#include "fastcgi.h"
#include <sqlite3.h>

#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif

#ifdef WIN32
static void child_init_handler(apr_pool_t *, server_rec *)
{

}

inline std::string & fixNamedPipe(std::string & inout)
{
	std::string front("\\\\.\\pipe\\"), nout;
	const size_t maxLen = 256-front.size();
	bool lastAt = false;

	for (std::string::iterator it = inout.begin(), end = inout.end(); it != end; ++it)
	{
		if (*it == '\\' || *it == '/')
		{
			if (!lastAt)
			{
				nout.append(1, '@');
				lastAt = true;
			}
		}
		else
		{
			nout.append(1, *it);
			lastAt = false;
		}
	}
	if (nout.size() > maxLen)
		inout = front+nout.substr(nout.size()-maxLen, maxLen);
	else
		inout = front+nout;
	return inout;
}
inline const char * _formatMessage(DWORD code, std::string & outStr)
{
	char lpMsgBuf[256];
	if (int num = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
			NULL, code, 
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), lpMsgBuf, 256, NULL))
	{
		lpMsgBuf[num] = '\0';
		outStr = lpMsgBuf;
		return outStr.c_str();
	}
	return "Unknown Error";
}
#else

#endif

#if (AP_SERVER_MAJORVERSION_NUMBER == 2) && (AP_SERVER_MINORVERSION_NUMBER < 4)

#define AP_LOG_FAIL(F,S) \
	ap_log_cerror(__FILE__, __LINE__, APLOG_CRIT, 0, r->connection, F,S);
#define AP_LOG_FAIL_2(F,S,S2) \
	ap_log_cerror(__FILE__, __LINE__, APLOG_CRIT, 0, r->connection, F,S,S2);
#define AP_LOG_FAIL_3(F,S,S2,S3) \
	ap_log_cerror(__FILE__, __LINE__, APLOG_CRIT, 0, r->connection, F,S,S2,S3);
#define AP_LOG_FAIL_4(F,S,S2,S3,S4) \
	ap_log_cerror(__FILE__, __LINE__, APLOG_CRIT, 0, r->connection, F,S,S2,S3,S4);

#else

#define AP_LOG_FAIL(F,S) \
	ap_log_cerror(__FILE__, __LINE__, APLOG_CRIT, 0, 500, r->connection, F,S);
#define AP_LOG_FAIL_2(F,S,S2) \
	ap_log_cerror(__FILE__, __LINE__, APLOG_CRIT, 0, 500, r->connection, F,S,S2);
#define AP_LOG_FAIL_3(F,S,S2,S3) \
	ap_log_cerror(__FILE__, __LINE__, APLOG_CRIT, 0, 500, r->connection, F,S,S2,S3);
#define AP_LOG_FAIL_4(F,S,S2,S3,S4) \
	ap_log_cerror(__FILE__, __LINE__, APLOG_CRIT, 0, 500, r->connection, F,S,S2,S3,S4);

#endif

#define X_BUFFER_SIZE (1024*128) // when reading writing X_STDIN
enum { FCGI_X_STDIN = 50 };

static int perfect_handler (request_rec *r);

#if CACHE_HOSTS
static char * cached_host = (char*)malloc(1024);
static char * cached_home = (char*)malloc(2048);

inline const char * is_cached_host(const char * host, server_rec *s)
{
	if (cached_host && strcasecmp(cached_host, host) == 0)
	{
//		ap_log_error(__FILE__, __LINE__, APLOG_NOTICE, 0, s, "%s %s", "cached host", host);
		return cached_home;
	}
//	ap_log_error(__FILE__, __LINE__, APLOG_NOTICE, 0, s, "%s %s", "uncached host", host);
	return NULL;
}

inline void cache_host(const char * host, const char * home, server_rec *s)
{
	size_t len = strlen(host),
		len2 = strlen(home);
	strncpy(cached_host, host, len<1023?len:1023);
	strncpy(cached_home, home, len2<2047?len2:2047);
	cached_host[len<1023?len:1023] = cached_home[len2<2047?len2:2047] = 0;
	
//	ap_log_error(__FILE__, __LINE__, APLOG_NOTICE, 0, s, "%s %s %s", "caching host", host, home);
}
#endif

struct header_gather
{
	std::string buffer;
	request_rec * r;
};

#ifdef _WINDOWS
_declspec(dllexport)
#else
static
#endif
	void register_9hooks(apr_pool_t *p);
void register_9hooks(apr_pool_t *p)
{
	ap_hook_handler(perfect_handler, NULL, NULL, APR_HOOK_MIDDLE);
#ifdef WIN32
	ap_hook_child_init(child_init_handler,NULL,NULL,APR_HOOK_MIDDLE);
#endif
	// ADD A WEBSOCKET HANDLER
}

static void writeRaw(std::string & buffer, const void * data, size_t size)
{
	buffer.append((const char*)data, size);
}

static void writeMsg(request_rec *r, std::string & buffer, uint8_t type, const void * data, uint16_t size)
{
//	AP_LOG_FAIL_3("%s %d %d", "writeMsg", (int)type, (int)size);
	FCGI_Header fcgiHead = {
		FCGI_VERSION_1,
		type,
		0,
		htons(size), 
		static_cast<uint8_t>(size%8),
		0};
	writeRaw(buffer, &fcgiHead, sizeof(fcgiHead));
	writeRaw(buffer, data, size);
	if (size%8)
	{
		uint8_t z[7] = {0};
		writeRaw(buffer, z, size%8);
	}
}

inline void addNameValue(request_rec *r, std::string & buffer, const char * name, const char * value)
{
	if (!name)
		return;
	if (!value)
		value = "";
	
//	AP_LOG_FAIL_2("(%s = %s)", name, value);
	
	size_t nLen = strlen(name),
		vLen = strlen(value);
	
	if (nLen > 0x7fffffff) 
		nLen = 0x7fffffff;
	if (vLen > 0x7fffffff) 
		vLen = 0x7fffffff;

	if (nLen > 127) 
	{
		buffer.append(1, ((nLen >> 24) & 0xff) | 0x80);
		buffer.append(1, (nLen >> 16) & 0xff);
		buffer.append(1, (nLen >> 8) & 0xff);
		buffer.append(1, (nLen >> 0) & 0xff);
	} 
	else 
	{
		buffer.append(1, (nLen >> 0) & 0xff);
	}

	if (vLen > 127) 
	{
		buffer.append(1, ((vLen >> 24) & 0xff) | 0x80);
		buffer.append(1, (vLen >> 16) & 0xff);
		buffer.append(1, (vLen >> 8) & 0xff);
		buffer.append(1, (vLen >> 0) & 0xff);
	} 
	else 
	{
		buffer.append(1, (vLen >> 0) & 0xff);
	}
	buffer.append(name);
	buffer.append(value);
}

inline void addNameValue(request_rec *r, std::string & buffer, const char * name, int value)
{
	char tmp[1024];
	sprintf(tmp, "%d", value);
	addNameValue(r, buffer, name, tmp);
}

static int find_initial_headers(void * data, const char * key, const char * val)
{
	header_gather * fnd = (header_gather*)data;
	addNameValue(fnd->r, fnd->buffer, key, val);
	return TRUE;
}

static int socket_read_content(request_rec *r, SOCKET sock, char * data, size_t len, size_t padding)
{
	while(len > 0)
	{
#ifdef WIN32
		DWORD read = 0;
		BOOL res = ReadFile((HANDLE)sock, data, (DWORD)len, &read, NULL);
		if (!res)
			return -1;
		len -= read;
		data += read;
#else
		size_t res = recv(sock, data, (int)len, 0);
		if (res < 1)
		{
			AP_LOG_FAIL_4("%s %d %d %s", "Error from recv:", (int)res, (int)errno, strerror(errno));
			return -1;
		}
		len -= res;
		data += res;
#endif
	}
	if (padding > 0)
	{
		char pd[7] = {0};
		return socket_read_content(r, sock, pd, padding, 0);
	}
	return 0;
}

static int socket_read_header(request_rec *r, SOCKET sock, FCGI_Header * header)
{
	size_t len = FCGI_HEADER_LEN;
	char * data = (char*)header;
	
	while(len > 0)
	{
#ifdef WIN32
		DWORD read = 0;
		BOOL res = ReadFile((HANDLE)sock, data, (DWORD)len, &read, NULL);
		if (!res)
			return -1;
		len -= read;
		data += read;
#else
		size_t res = recv(sock, data, (int)len, 0);
		if (res < 1)
			return -1;
		len -= res;
		data += res;
#endif
	}
	return 0;
}

static int socket_write(request_rec *r, SOCKET sock, const char * data, size_t len)
{
	while(len > 0)
	{
#ifdef WIN32
		DWORD wrote = 0;
		BOOL res = WriteFile((HANDLE)sock, data, (DWORD)len, &wrote, NULL);
		if (!res)
			return -1;
		len -= wrote;
		data += wrote;
#else
		ssize_t res = send(sock, data, (int)len, 0);
		if (res == -1)
			return -1;
		len -= res;
		data += res;
#endif
	}
	return 0;
}


static int pull_header_line(const char *& data, uint16_t & len, 
							std::string & name, std::string & value)
{
	if (data[0] == '\r')
	{
		++data;
		--len;
		if (data[0] == '\n')
		{
			++data;
			--len;
		}
		return 0;
	}
	if (data[0] == '\n')
	{
		++data;
		--len;
		return 0;
	}

	while(len)
	{
		if (*data == ':')
		{
			++data;
			--len;
			while(len && isspace(*data))
			{
				++data;
				--len;		
			}
			break;
		}
		name.append(1, *data);
		++data;
		--len;
	}
	
	while(len)
	{
		if (*data == '\r')
		{
			++data;
			--len;
			if (*data == '\n')
			{
				++data;
				--len;
			}
			if (*data == ' ' || *data == '\t') // wrapped
			{
				while(len && (*data == ' ' || *data == '\t'))
				{
					++data;
					--len;
				}
			}
			else
			{
				break;
			}
		}
		value.append(1, *data);
		++data;
		--len;
	}
	return 1;
}

int perfect_handler(request_rec *r)
{
//	AP_LOG_FAIL_2("%s %s", "got request", r->handler);

	if (strncmp(r->handler,"perfect", 7) != 0 && strcmp(r->handler, "application/x-httpd-perfect") != 0)
		return DECLINED;
#ifdef WIN32
	std::string matchHome,
		matchSocket;
#else
	const char * matchHome = NULL,
		* matchSocket = NULL;
#endif
	int res = 0;
	FCGI_BeginRequestBody brb = {FCGI_RESPONDER, 0, {0,0,0,0,0}};
	
	std::string body;
	header_gather fnd;
	
	matchHome = ap_context_document_root(r);
	matchSocket = "/../perfect.fastcgi.sock";

	SOCKET sock = INVALID_SOCKET;
#ifdef WIN32
	DWORD error;
	fixNamedPipe(matchSocket);
	do {
		sock = (SOCKET)CreateFileA(matchSocket.c_str(), GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		error = GetLastError();
	} while(sock == INVALID_SOCKET && error == ERROR_PIPE_BUSY);
	if (prep)
		sqlite3_finalize(prep);
	if (sql)
		sqlite3_close(sql);
	if (sock == INVALID_SOCKET)
	{
		std::string errorS;
		AP_LOG_FAIL_4("%s%s %d %s", "Unable to connect on: ", matchSocket.c_str(), error, _formatMessage(error, errorS));
		goto close_denied;
	}
#else
	sock = socket(AF_UNIX, SOCK_STREAM, 0);	
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, matchHome);
	strcat(addr.sun_path, matchSocket);
	
	res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (res != 0)
	{
		close(sock);
		AP_LOG_FAIL_4("%s%s %d %s", "Unable to connect on: ", addr.sun_path, errno, strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	int sockBufferSize = X_BUFFER_SIZE;
	res = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sockBufferSize, sizeof(sockBufferSize));
	if (res != 0)
	{
		AP_LOG_FAIL("%s", "Couldn't set SO_SNDBUF");
	}
	res = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sockBufferSize, sizeof(sockBufferSize));
	if (res != 0)
	{
		AP_LOG_FAIL("%s", "Couldn't set SO_RCVBUF");
	}
#endif
	fnd.r = r;
	
	writeMsg(r, body, FCGI_BEGIN_REQUEST, &brb, sizeof(brb));

	ap_add_common_vars(r);
    ap_add_cgi_vars(r);
	apr_table_do(find_initial_headers, &fnd, r->subprocess_env, NULL);	

	const char * authStr = apr_table_get(r->headers_in, "Authorization");
	if (authStr)
		addNameValue(r, fnd.buffer, "HTTP_AUTHORIZATION", authStr);
	addNameValue(r, fnd.buffer, "L_APACHE_HANDLER", r->handler);
	addNameValue(r, fnd.buffer, "", "");
	writeMsg(r, body, FCGI_PARAMS, fnd.buffer.c_str(), (uint16_t)fnd.buffer.size());
	
	res = socket_write(r, sock, body.c_str(), body.size());
	if (res != 0)
	{
		CLOSE_SOCKET(sock);
		AP_LOG_FAIL("%s", "Unable to initiate request");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	body.clear();
	
	// POST ARGS
	int toRead = 0;
	
    if ( ap_setup_client_block(r, REQUEST_CHUNKED_ERROR) == OK )
    {
		if ( ap_should_client_block(r) == 1)
		{
			std::string buffers;
			char buffer[X_BUFFER_SIZE];
			long readLen = 0;
			toRead = (int)r->remaining;
			uint32_t readSize = X_BUFFER_SIZE;
//			bool isX = toRead > X_BUFFER_SIZE; // extension for greater throughput

			uint32_t swappedRead = htonl(toRead);
			writeMsg(r, body, FCGI_X_STDIN, (void*)&swappedRead, sizeof(uint32_t));	
			
			while ( (readLen = ap_get_client_block(r, buffer, readSize)) > 0 )
			{	
//				AP_LOG_FAIL_3("%s %d %d", "Read post ", readLen, toRead);
			 
			 	if (buffers.size() + readLen > X_BUFFER_SIZE)
			 	{
			 		body.append(buffers);
					res = socket_write(r, sock, body.c_str(), body.size());
//					AP_LOG_FAIL_3("%s %ld %d", "wrote 1", body.size(), toRead);
					if (res != 0)
					{
						CLOSE_SOCKET(sock);
						AP_LOG_FAIL("%s", "Unable to send post");
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					body.clear();
					buffers.clear();
				}
				buffers.append(buffer, readLen);
			    toRead -= readLen;
			    readSize = toRead < X_BUFFER_SIZE ? toRead : X_BUFFER_SIZE;
			}
			if (readLen == -1)
			{
				CLOSE_SOCKET(sock);// client terminated
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			if (buffers.size() > 0)
			{
				body.append(buffers);
				res = socket_write(r, sock, body.c_str(), body.size());
//				AP_LOG_FAIL_3("%s %ld %d", "wrote 2", body.size(), toRead);
				if (res != 0)
				{
					CLOSE_SOCKET(sock);
					AP_LOG_FAIL("%s", "Unable to send post");
					return HTTP_INTERNAL_SERVER_ERROR;
				}
				body.clear();
			}
		}
    }
	
	writeMsg(r, body, FCGI_STDIN, NULL, 0);
	res = socket_write(r, sock, body.c_str(), body.size());
	if (res != 0)
	{
		CLOSE_SOCKET(sock);
		AP_LOG_FAIL("%s", "Unable to initiate request");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	bool inBody = false;
	FCGI_Header readHead;
	memset(&readHead, 0, sizeof(readHead));
	res = socket_read_header(r, sock, &readHead);
	while(res == 0)
	{
		const char * contentData = NULL;
		uint16_t contentSize = ntohs(readHead.contentLength);
		
//		AP_LOG_FAIL_3("%s %d %d", "Got header ", contentSize, readHead.type);
		
		body.clear();
		if (contentSize)
		{	
			body.append(contentSize, 0);
			res = socket_read_content(r, sock, (char*)body.data(), contentSize, readHead.paddingLength);
			if (res != 0)
			{
				CLOSE_SOCKET(sock);
				AP_LOG_FAIL_3("%s %d %s", "Unable to read content", contentSize, r->uri);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			contentData = body.c_str();
//			AP_LOG_FAIL_2("%s%s", "content ", contentData);
		}
		switch(readHead.type)
		{
			case FCGI_STDOUT:
				if (contentSize)
				{	
					while (!inBody && contentSize)
					{
						std::string name, value;
						res = pull_header_line(contentData, contentSize, name, value);
//						AP_LOG_FAIL_3("%s %s %s", "header", name.c_str(), value.c_str());
						if (res == 0)
						{
							inBody = true;
//							AP_LOG_FAIL_2("%s %d", "moving to body", contentSize);
							ap_send_http_header(r);
						}
						else
						{
							if (strcasecmp(name.c_str(), "status") == 0)
							{
								r->status = atoi(value.c_str());
							}
							else if ( strcasecmp(name.c_str(), "content-type") == 0 )
							{
								ap_set_content_type(r, apr_pstrdup(r->pool, value.c_str()));
							}
							else
							{
								apr_table_add(r->headers_out, name.c_str(), value.c_str());
							}
						}	
					}
					if (inBody && contentSize)
					{
						apr_bucket_brigade * bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
						apr_bucket * b = apr_bucket_heap_create(contentData, contentSize, NULL, r->connection->bucket_alloc);
						APR_BRIGADE_INSERT_TAIL(bb, b);
						APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_flush_create(r->connection->bucket_alloc));
						ap_pass_brigade(r->output_filters, bb);
					}
				}
				break;
			case FCGI_END_REQUEST:
				goto close_ok;
			case FCGI_ABORT_REQUEST:
				goto close_denied;
		}
		memset(&readHead, 0, sizeof(readHead));
		res = socket_read_header(r, sock, &readHead);
	}
	
close_ok:
	CLOSE_SOCKET(sock);
	ap_finalize_request_protocol(r);
	return OK;
	
close_denied:
	CLOSE_SOCKET(sock);
	return HTTP_INTERNAL_SERVER_ERROR;
}

extern "C"
{
	module AP_MODULE_DECLARE_DATA perfect_module =
	{
		STANDARD20_MODULE_STUFF,
		NULL,			/* dir config creator */
		NULL,			/* dir merger ensure strictness */
		NULL,//create_mod_lasso9_config, /* server config */
		NULL,			/* merge server config */
		NULL,			/* command table */
		register_9hooks,		/* register hooks */
	};
}

