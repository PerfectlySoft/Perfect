//
//  curl_support.hpp
//  lasso_lib
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

#ifndef curl_support_hpp
#define curl_support_hpp

#include <stdio.h>
#include "curl/curl.h"

#ifdef  __cplusplus
extern "C" {
#endif
	
	typedef size_t (*curl_func)(void * ptr, size_t size, size_t num, void * ud);
	
	CURLcode curl_easy_setopt_long(CURL *handle, CURLoption option, long value);
	CURLcode curl_easy_setopt_cstr(CURL *handle, CURLoption option, const char * value);
	CURLcode curl_easy_setopt_int64(CURL *handle, CURLoption option, int64_t value);
	CURLcode curl_easy_setopt_slist(CURL *handle, CURLoption option, struct curl_slist * slist);
	CURLcode curl_easy_setopt_void(CURL *handle, CURLoption option, void * value);
	CURLcode curl_easy_setopt_func(CURL *handle, CURLoption option, curl_func value);
	
	CURLcode curl_easy_getinfo_long(CURL *handle, CURLINFO option, long * value);
	CURLcode curl_easy_getinfo_cstr(CURL *handle, CURLINFO option, const char ** value);
	CURLcode curl_easy_getinfo_double(CURL *handle, CURLINFO option, double * value);
	CURLcode curl_easy_getinfo_slist(CURL *handle, CURLINFO option, struct curl_slist ** value);
	
	CURLcode curl_get_msg_result(CURLMsg * msg);
#ifdef  __cplusplus
}
#endif
#endif /* curl_support_hpp */
