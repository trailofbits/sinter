/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation
import Logger
import Configuration

public enum EndpointSecurityError: Error {
    case unknownError
    case initializationError
    case cacheClearError
    case subscriptionError
}

public typealias EndpointSecurityCallback = (_ message: EndpointSecurityMessage) -> Void

public typealias EndpointSecurityInterfaceFactory = (LoggerInterface,
                                                     @escaping EndpointSecurityCallback) -> Result<EndpointSecurityInterface, Error>

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

public enum EndpointSecurityFileChangeNotificationType : CaseIterable {
    case unknown
    case write
    case unlink
    case rename
    case mmap
    case link
    case truncate
    case create
}

public struct EndpointSecurityFileChangeNotification {
    public init(type: EndpointSecurityFileChangeNotificationType,
                pathList: [String]) {

        self.type = type
        self.pathList = pathList
    }

    public let type: EndpointSecurityFileChangeNotificationType
    public let pathList: [String]
}

public enum EndpointSecurityExecInvalidationNotificationReason {
    case expired
    case applicationChanged
}

public struct EndpointSecurityExecInvalidationNotification {
    public init(identifier: Int64,
                binaryPath: String,
                reason: EndpointSecurityExecInvalidationNotificationReason) {
        self.identifier = identifier
        self.binaryPath = binaryPath
        self.reason = reason
    }

    public var identifier: Int64
    public var binaryPath: String
    public var reason: EndpointSecurityExecInvalidationNotificationReason
}

public enum EndpointSecurityMessage {
    case ExecAuthorization(EndpointSecurityExecAuthorization)
    case ChangeNotification(EndpointSecurityFileChangeNotification)
    case ExecInvalidationNotification(EndpointSecurityExecInvalidationNotification)
}

public protocol EndpointSecurityInterface {
    func setAuthorization(identifier: Int64, allow: Bool, cache: Bool) -> Bool
    func invalidateCache() -> Bool
}
