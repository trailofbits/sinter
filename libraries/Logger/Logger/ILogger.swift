/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public enum AuthorizationLogMessageReason {
    case userAction
    case cached
    case rule
    case unsigned
    case tampered
}

public struct AuthorizationLogMessage {
    public var timestamp: Int64
    public var allowed: Bool
    public var cached: Bool
    public var teamId: String
    public var cdHash: String
    public var binaryPath: String
    public var reason: AuthorizationLogMessageReason

    public init(timestamp: Int64, allowed: Bool, cached: Bool,
                teamId: String, cdHash: String, binaryPath: String,
                reason: AuthorizationLogMessageReason) {
        self.timestamp = timestamp
        self.allowed = allowed
        self.cached = cached
        self.teamId = teamId
        self.cdHash = cdHash
        self.binaryPath = binaryPath
        self.reason = reason
    }
}

public enum LogMessageSeverity {
    case debug
    case information
    case warning
    case error
}

public protocol ILogger {
    func logAuthorization(message: AuthorizationLogMessage)
    func logMessage(severity: LogMessageSeverity, message: String)
}
