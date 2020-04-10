/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

// EndpointSecurity uses either SHA1 or SHA256 hashes, but can
// only represent 20 bytes so SHA256 hashes are truncated
public enum BinaryHashType {
    case sha1
    case truncatedSha256
}

public struct BinaryHash {
    public init(type: BinaryHashType, hash: String) {
        self.type = type
        self.hash = hash
    }

    public var type: BinaryHashType
    public var hash: String
}
