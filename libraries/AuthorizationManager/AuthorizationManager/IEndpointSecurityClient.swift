/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public struct IEndpointSecurityClientMessage {
    public var messageId: Int64
    public var binaryPath: String

    public init(messageId: Int64, binaryPath: String) {
        self.messageId = messageId
        self.binaryPath = binaryPath
    }
}

public protocol IEndpointSecurityClient {
    func setCallback(callback: @escaping (_ message: IEndpointSecurityClientMessage) -> Void)
    func setAuthorization(messageId: Int64, allow: Bool, cache: Bool)
    func invalidateCachedAuthorization(binaryPath: String)
}
