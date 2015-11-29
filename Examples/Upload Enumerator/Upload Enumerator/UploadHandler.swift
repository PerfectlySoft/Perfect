//
//  UploadHandler.swift
//  Upload Enumerator
//
//  Created by Kyle Jessup on 2015-11-05.
//	Copyright (C) 2015 PerfectlySoft, Inc.
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Affero General Public License as
//	published by the Free Software Foundation, either version 3 of the
//	License, or (at your option) any later version, as supplemented by the
//	Perfect Additional Terms.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Affero General Public License, as supplemented by the
//	Perfect Additional Terms, for more details.
//
//	You should have received a copy of the GNU Affero General Public License
//	and the Perfect Additional Terms that immediately follow the terms and
//	conditions of the GNU Affero General Public License along with this
//	program. If not, see <http://www.perfect.org/AGPL_3_0_With_Perfect_Additional_Terms.txt>.
//

import PerfectLib

// This is the function which all Perfect Server modules must expose.
// The system will load the module and call this function.
// In here, register any handlers or perform any one-time tasks.
public func PerfectServerModuleInit() {
	
	// Register our handler class with the PageHandlerRegistry.
	// The name "UploadHandler", which we supply here, is used within a moustache template to associate the template with the handler.
	PageHandlerRegistry.addPageHandler("UploadHandler") {
		
		// This closure is called in order to create the handler object.
		// It is called once for each relevant request.
		// The supplied WebResponse object can be used to tailor the return value.
		// However, all request processing should take place in the `valuesForResponse` function.
		(r:WebResponse) -> PageHandler in
		
		return UploadHandler()
	}
	
}

// Handler class
// When referenced in a moustache template, this class will be instantiated to handle the request
// and provide a set of values which will be used to complete the template.
class UploadHandler: PageHandler { // all template handlers must inherit from PageHandler
	
	// This is the function which all handlers must impliment.
	// It is called by the system to allow the handler to return the set of values which will be used when populating the template.
	// - parameter context: The MoustacheEvaluationContext which provides access to the WebRequest containing all the information pertaining to the request
	// - parameter collector: The MoustacheEvaluationOutputCollector which can be used to adjust the template output. For example a `defaultEncodingFunc` could be installed to change how outgoing values are encoded.
	func valuesForResponse(context: MoustacheEvaluationContext, collector: MoustacheEvaluationOutputCollector) throws -> MoustacheEvaluationContext.MapType {

        print("UploadHandler got request")
        
        var values:[String:Any] = ["title": "Upload Enumerator"]
        
        // Grab the WebRequest so we can get information about what was uploaded
        guard let request = context.webRequest else {
            return values
        }
        
        // Grab the fileUploads array and see what's there
        // If this POST was not multi-part, then this array will be empty
        let uploads = request.fileUploads
        // Create an array of dictionaries which will show what was uploaded
        // This array will be used in the corresponding moustache template
        let files:[[String:Any]] = uploads.map {
            [
                "fieldName": $0.fieldName,
                "contentType": $0.contentType,
                "fileName": $0.fileName,
                "fileSize": $0.fileSize,
                "tmpFileName": $0.tmpFileName
            ]
        }
        values["files"] = files
        values["count"] = files.count
        
        // Grab the regular form parameters
        let params = request.params()
        // Create an array of dictionaries which will show what was posted
        // This will not include any uploaded files. Those are handled above.
        let formattedParams:[[String:Any]]? = params?.map {
            [
                "paramName":$0.0,
                "paramValue":$0.1
            ]
        }
        
        if let formattedParams = formattedParams {
            values["params"] = formattedParams
            values["paramsCount"] = formattedParams.count
        }
        
        return values
	}
}
