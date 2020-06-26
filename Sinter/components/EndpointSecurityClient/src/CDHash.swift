/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation
import EndpointSecurity

// Because a Swift tuple cannot/shouldn't be iterated at runtime,
// use an UnsafeBufferPointer to store the twenty UInt8 values of
// the cdhash (a tuple of UInt8 values) into an iterable array form
struct CDhash {
    public var tuple: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                       UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                       UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)

    public var array: [UInt8] {
        var tmp = tuple
        return [UInt8](UnsafeBufferPointer(start: &tmp.0, count: MemoryLayout.size(ofValue: tmp)))
    }
}
