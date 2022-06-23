
#ifndef _p_curl_h_
#define _p_curl_h_

#include <curl/curl.h>

#ifdef CURLOPT_HEADERDATA
#undef CURLOPT_HEADERDATA
CURLoption CURLOPT_HEADERDATA = CURLOPT_WRITEHEADER;
#endif
#ifdef CURLOPT_WRITEDATA
#undef CURLOPT_WRITEDATA
CURLoption CURLOPT_WRITEDATA = CURLOPT_FILE;
#endif
#ifdef CURLOPT_READDATA
#undef CURLOPT_READDATA
CURLoption CURLOPT_READDATA = CURLOPT_INFILE;
#endif

typedef size_t (*curl_func)(void * ptr, size_t size, size_t num, void * ud);

static CURLcode curl_easy_setopt_long(CURL *handle, CURLoption option, long value)
{
	return curl_easy_setopt(handle, option, value);
}

static CURLcode curl_easy_setopt_cstr(CURL *handle, CURLoption option, const char * value)
{
	return curl_easy_setopt(handle, option, value);
}

static CURLcode curl_easy_setopt_int64(CURL *handle, CURLoption option, long long value)
{
	return curl_easy_setopt(handle, option, value);
}

static CURLcode curl_easy_setopt_slist(CURL *handle, CURLoption option, struct curl_slist * value)
{
	return curl_easy_setopt(handle, option, value);
}

static CURLcode curl_easy_setopt_void(CURL *handle, CURLoption option, void * value)
{
	return curl_easy_setopt(handle, option, value);
}

static CURLcode curl_easy_setopt_func(CURL *handle, CURLoption option, curl_func value)
{
	return curl_easy_setopt(handle, option, value);
}

static CURLcode curl_easy_getinfo_long(CURL *handle, CURLINFO option, long * value)
{
	return curl_easy_getinfo(handle, option, value);
}

static CURLcode curl_easy_getinfo_cstr(CURL *handle, CURLINFO option, const char ** value)
{
	return curl_easy_getinfo(handle, option, value);
}

static CURLcode curl_easy_getinfo_double(CURL *handle, CURLINFO option, double * value)
{
	return curl_easy_getinfo(handle, option, value);
}

static CURLcode curl_easy_getinfo_slist(CURL *handle, CURLINFO option, struct curl_slist ** value)
{
	return curl_easy_getinfo(handle, option, value);
}

static CURLcode curl_get_msg_result(CURLMsg * msg)
{
	return msg->data.result;
}

static CURLFORMcode curl_formadd_content(struct curl_httppost **firstitem, struct curl_httppost **lastitem,
	const char * name, const char * content, const long size, const char * type) {
		return type ?
			curl_formadd(firstitem, lastitem,
							CURLFORM_COPYNAME, name,
							CURLFORM_COPYCONTENTS, content,
							CURLFORM_CONTENTSLENGTH, size,
							CURLFORM_CONTENTTYPE, type,
							CURLFORM_END)
			 :
			curl_formadd(firstitem, lastitem,
							CURLFORM_COPYNAME, name,
							CURLFORM_COPYCONTENTS, content,
							CURLFORM_CONTENTSLENGTH, size,
							CURLFORM_END);
}

static CURLFORMcode curl_formadd_file(struct curl_httppost **firstitem, struct curl_httppost **lastitem,
	const char * name, const char * path, const char * type) {
		return type ?
			curl_formadd(firstitem, lastitem,
						   CURLFORM_COPYNAME, name,
						   CURLFORM_CONTENTTYPE, type,
						   CURLFORM_FILE, path,
						   CURLFORM_END)
			:
			curl_formadd(firstitem, lastitem,
							CURLFORM_COPYNAME, name,
							CURLFORM_FILE, path,
							CURLFORM_END);
}

static CURLcode curl_form_post(CURL * handle, struct curl_httppost * post) {
	return curl_easy_setopt(handle, CURLOPT_HTTPPOST, post);
}


#endif
