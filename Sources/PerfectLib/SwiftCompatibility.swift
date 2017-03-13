//
//  SwiftCompatibility.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2016-04-22.
//  Copyright © 2016 PerfectlySoft. All rights reserved.
//

import Foundation

extension String {
    func range(ofString string: String, ignoreCase: Bool = false) -> Range<String.Index>? {
        var idx = self.startIndex
        let endIdx = self.endIndex
        
        while idx != endIdx {
            if ignoreCase ? (String(self[idx]).lowercased() == String(string[string.startIndex]).lowercased()) : (self[idx] == string[string.startIndex]) {
                var newIdx = self.index(after: idx)
                var findIdx = string.index(after: string.startIndex)
                let findEndIdx = string.endIndex
                
                while newIdx != endIndex && findIdx != findEndIdx && (ignoreCase ? (String(self[newIdx]).lowercased() == String(string[findIdx]).lowercased()) : (self[newIdx] == string[findIdx])) {
                    newIdx = self.index(after: newIdx)
                    findIdx = string.index(after: findIdx)
                }
                
                if findIdx == findEndIdx { // match
                    return idx..<newIdx
                }
            }
            idx = self.index(after: idx)
        }
        return nil
    }
}
