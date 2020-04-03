/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public struct ISignatureDatabaseResult {
    public var identifier: Int64
    public var validSignature: Bool

    public init(identifier: Int64, validSignature: Bool) {
        self.identifier = identifier
        self.validSignature = validSignature
    }
}

public protocol ISignatureDatabase {
    func checkSignatureFor(message: IEndpointSecurityClientMessage,
                           block: @escaping (_ message: IEndpointSecurityClientMessage, _ valid: Bool) -> Void)

    func invalidateCacheFor(path: String)
}
