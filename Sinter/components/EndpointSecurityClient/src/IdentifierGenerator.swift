/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

struct IndentifierGenerator {
    @Atomic private var identifierGenerator: Int64 = 0
    
    public mutating func generate() -> Int64 {
        identifierGenerator += 1
        return identifierGenerator
    }
}

var identifierGenerator = IndentifierGenerator()
