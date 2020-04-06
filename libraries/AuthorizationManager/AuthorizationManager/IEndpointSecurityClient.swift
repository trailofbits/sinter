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

    public var ppid: pid_t
    public var pid: pid_t

    public var uid: uid_t
    public var gid: gid_t

    public var cdhash: String
    public var signingId: String
    public var teamId: String
    public var isAppleSigned: Bool

    public init(messageId: Int64,
                binaryPath: String,
                parentProcessId: pid_t,
                processId: pid_t,
                userId: uid_t,
                groupId: gid_t,
                cdhash: String,
                signingId: String,
                teamId: String,
                isAppleSigned: Bool) {
        self.messageId = messageId
        self.binaryPath = binaryPath
        ppid = parentProcessId
        pid = processId
        uid = userId
        gid = groupId
        self.cdhash = cdhash
        self.signingId = signingId
        self.teamId = teamId
        self.isAppleSigned = isAppleSigned
    }
}

public protocol IEndpointSecurityClient {
    func setCallback(callback: @escaping (_ message: IEndpointSecurityClientMessage) -> Void)
    func setAuthorization(messageId: Int64, allow: Bool, cache: Bool)
    func invalidateCachedAuthorization(binaryPath: String)
}
