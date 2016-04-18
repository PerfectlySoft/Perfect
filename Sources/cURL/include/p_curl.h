
#ifndef _p_curl_h_
#define _p_curl_h_

#include <curl/curl.h>

typedef size_t (*curl_func)(void * ptr, size_t size, size_t num, void * ud);

extern inline CURLcode curl_easy_setopt_long(CURL *handle, CURLoption option, long value)
{
	return curl_easy_setopt(handle, option, value);
}

extern inline CURLcode curl_easy_setopt_cstr(CURL *handle, CURLoption option, const char * value)
{
	return curl_easy_setopt(handle, option, value);
}

extern inline CURLcode curl_easy_setopt_int64(CURL *handle, CURLoption option, int64_t value)
{
	return curl_easy_setopt(handle, option, value);
}

extern inline CURLcode curl_easy_setopt_slist(CURL *handle, CURLoption option, struct curl_slist * value)
{
	return curl_easy_setopt(handle, option, value);
}

extern inline CURLcode curl_easy_setopt_void(CURL *handle, CURLoption option, void * value)
{
	return curl_easy_setopt(handle, option, value);
}

extern inline CURLcode curl_easy_setopt_func(CURL *handle, CURLoption option, curl_func value)
{
	return curl_easy_setopt(handle, option, value);
}

extern inline CURLcode curl_easy_getinfo_long(CURL *handle, CURLINFO option, long * value)
{
	return curl_easy_getinfo(handle, option, value);
}

extern inline CURLcode curl_easy_getinfo_cstr(CURL *handle, CURLINFO option, const char ** value)
{
	return curl_easy_getinfo(handle, option, value);
}

extern inline CURLcode curl_easy_getinfo_double(CURL *handle, CURLINFO option, double * value)
{
	return curl_easy_getinfo(handle, option, value);
}

extern inline CURLcode curl_easy_getinfo_slist(CURL *handle, CURLINFO option, struct curl_slist ** value)
{
	return curl_easy_getinfo(handle, option, value);
}

extern inline CURLcode curl_get_msg_result(CURLMsg * msg)
{
	return msg->data.result;
}

#endif
