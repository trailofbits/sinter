/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Logger
import Configuration
import EndpointSecurityClient

public enum DecisionManagerError: Error {
    case unknownError
    case invalidConfiguration
}

public struct DecisionManagerRequest {
    public var binaryPath: String
    public var codeDirectoryHash: BinaryHash
    public var signingIdentifier: String
    public var teamIdentifier: String
    public var platformBinary: Bool

    public init(binaryPath: String,
                codeDirectoryHash: BinaryHash,
                signingIdentifier: String,
                teamIdentifier: String,
                platformBinary: Bool) {

        self.binaryPath = binaryPath
        self.codeDirectoryHash = codeDirectoryHash
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.platformBinary = platformBinary
    }
}

public enum SignatureDatabaseResult : CaseIterable {
    case Valid
    case Invalid
    case NotSigned
    case Failed
}

public protocol DecisionManagerInterface {
    func processRequest(request: DecisionManagerRequest,
                        allow: inout Bool,
                        cache: inout Bool,
                        signatureCheckResult: SignatureDatabaseResult) -> Void
}

public func createLocalDecisionManager(logger: LoggerInterface,
                                       configuration: ConfigurationInterface) -> DecisionManagerInterface {

    let localRuleDatabaseProvider = LocalRuleDatabaseProvider(logger: logger)

    return BaseDecisionManager(logger: logger,
                               configuration: configuration,
                               ruleDatabaseProvider: localRuleDatabaseProvider)
}

public func createRemoteDecisionManager(logger: LoggerInterface,
                                       configuration: ConfigurationInterface) -> DecisionManagerInterface {

    let remoteRuleDatabaseProvider = RemoteRuleDatabaseProvider(logger: logger)

    return BaseDecisionManager(logger: logger,
                               configuration: configuration,
                               ruleDatabaseProvider: remoteRuleDatabaseProvider)
}
