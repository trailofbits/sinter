/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

@propertyWrapper
struct Atomic<Value> {
    private let queue = DispatchQueue(label: "com.trailofbits.sinter.atomic-property")
    private var value: Value

    init(wrappedValue: Value) {
        value = wrappedValue
    }

    var wrappedValue: Value {
        get {
            queue.sync {
                value
            }
        }
        set {
            queue.sync {
                value = newValue
            }
        }
    }
}

private let atomicQueue = DispatchQueue(label: "com.trailofbits.sinter.atomic")

func atomic(_ block: () -> Void) {
    atomicQueue.sync {
        block()
    }
}
