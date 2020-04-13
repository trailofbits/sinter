/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public enum EndpointSecurityError: Error {
    case unknownError
    case initializationError
    case cacheClearError
    case subscriptionError
}

public typealias EndpointSecurityCallback = (_ message: EndpointSecurityMessage) -> Void

public typealias EndpointSecurityInterfaceFactory = (LoggerInterface, @escaping EndpointSecurityCallback) -> Result<EndpointSecurityInterface, Error>

public struct EndpointSecurityExecAuthorization {
    public init(binaryPath: String, parentProcessId: pid_t,
                processId: pid_t, userId: uid_t, groupId: gid_t,
                codeDirectoryHash: BinaryHash, signingIdentifier: String,
                teamIdentifier: String, platformBinary: Bool) {
        self.binaryPath = binaryPath
        self.parentProcessId = parentProcessId
        self.processId = processId
        self.userId = userId
        self.groupId = groupId
        self.codeDirectoryHash = codeDirectoryHash
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.platformBinary = platformBinary
    }

    public var identifier: Int64 = 0
    public var binaryPath: String

    public var parentProcessId: pid_t
    public var processId: pid_t

    public var userId: uid_t
    public var groupId: gid_t

    public var codeDirectoryHash: BinaryHash
    public var signingIdentifier: String
    public var teamIdentifier: String
    public var platformBinary: Bool
}

public struct EndpointSecurityWriteNotification {
    public init(filePath: String) {
        self.filePath = filePath
    }

    public var filePath: String
}

public struct EndpointSecurityExecInvalidationNotification {
    public init(identifier: Int64, binaryPath: String) {
        self.identifier = identifier
        self.binaryPath = binaryPath
    }

    public var identifier: Int64
    public var binaryPath: String
}

public enum EndpointSecurityMessage {
    case ExecAuthorization(EndpointSecurityExecAuthorization)
    case WriteNotification(EndpointSecurityWriteNotification)
    case ExecInvalidationNotification(EndpointSecurityExecInvalidationNotification)
    case InvalidWriteNotification
}

public protocol EndpointSecurityInterface {
    func setAuthorization(identifier: Int64, allow: Bool, cache: Bool) -> Bool
    func invalidateCache() -> Bool
}
