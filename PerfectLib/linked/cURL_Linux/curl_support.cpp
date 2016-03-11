//
//  curl_support.cpp
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-08-11.
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


#include "curl_support.hpp"

CURLcode curl_easy_setopt_long(CURL *handle, CURLoption option, long value)
{
	return curl_easy_setopt(handle, option, value);
}

CURLcode curl_easy_setopt_cstr(CURL *handle, CURLoption option, const char * value)
{
	return curl_easy_setopt(handle, option, value);
}

CURLcode curl_easy_setopt_int64(CURL *handle, CURLoption option, int64_t value)
{
	return curl_easy_setopt(handle, option, value);
}

CURLcode curl_easy_setopt_slist(CURL *handle, CURLoption option, curl_slist * value)
{
	return curl_easy_setopt(handle, option, value);
}

CURLcode curl_easy_setopt_void(CURL *handle, CURLoption option, void * value)
{
	return curl_easy_setopt(handle, option, value);
}

CURLcode curl_easy_setopt_func(CURL *handle, CURLoption option, curl_func value)
{
	return curl_easy_setopt(handle, option, value);
}

CURLcode curl_easy_getinfo_long(CURL *handle, CURLINFO option, long * value)
{
	return curl_easy_getinfo(handle, option, value);
}

CURLcode curl_easy_getinfo_cstr(CURL *handle, CURLINFO option, const char ** value)
{
	return curl_easy_getinfo(handle, option, value);
}

CURLcode curl_easy_getinfo_double(CURL *handle, CURLINFO option, double * value)
{
	return curl_easy_getinfo(handle, option, value);
}

CURLcode curl_easy_getinfo_slist(CURL *handle, CURLINFO option, curl_slist ** value)
{
	return curl_easy_getinfo(handle, option, value);
}

CURLcode curl_get_msg_result(CURLMsg * msg)
{
	return msg->data.result;
}




