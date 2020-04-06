/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation
import Logger

class AuthorizationManager: IAuthorizationManager {
    private let authorizationInterface: IAuthorizationInterface
    private let signatureDatabase: ISignatureDatabase
    private let logger: ILogger
    private let endpointSecurityClient: IEndpointSecurityClient
    private let operationQueue = OperationQueue()

    init(authorizationInterface: IAuthorizationInterface,
         signatureDatabase: ISignatureDatabase,
         endpointSecurityClient: IEndpointSecurityClient,
         logger: ILogger,
         concurrentOperationCount: Int) {
        self.authorizationInterface = authorizationInterface
        self.signatureDatabase = signatureDatabase
        self.logger = logger

        self.endpointSecurityClient = endpointSecurityClient
        self.endpointSecurityClient.setCallback(callback: processEndpointSecurityMessage)

        operationQueue.maxConcurrentOperationCount = concurrentOperationCount
        operationQueue.qualityOfService = .userInteractive
    }

    private func processSignatureCheckNotification(message: IEndpointSecurityClientMessage, valid: Bool) {
        if !valid {
            let logMessage = AuthorizationLogMessage(
                timestamp: 0,
                allowed: false,
                cached: true,
                teamId: "todo",
                cdHash: "todo2",
                binaryPath: message.binaryPath,
                reason: AuthorizationLogMessageReason.unsigned
            )

            logger.logAuthorization(message: logMessage)
            endpointSecurityClient.setAuthorization(messageId: message.messageId, allow: false, cache: true)

        } else {
            let operation = AuthorizationManagerOperation(authorizationInterface: authorizationInterface,
                                                          message: message)

            operation.completionBlock = { [unowned operation, message] in
                let allow = operation.isAllowed()
                let cache = operation.cacheEnabled()
                self.endpointSecurityClient.setAuthorization(messageId: message.messageId, allow: allow, cache: cache)

                let logMessage = AuthorizationLogMessage(
                    timestamp: 0,
                    allowed: allow,
                    cached: cache,
                    teamId: "todo",
                    cdHash: "todo2",
                    binaryPath: message.binaryPath,
                    reason: AuthorizationLogMessageReason.userAction
                )

                self.logger.logAuthorization(message: logMessage)
            }

            operationQueue.addOperation(operation)
        }
    }

    private func processEndpointSecurityMessage(message: IEndpointSecurityClientMessage) {
        signatureDatabase.checkSignatureFor(message: message, block: processSignatureCheckNotification)
    }
}

private final class AuthorizationManagerOperation: Operation {
    private let authorizationInterface: IAuthorizationInterface
    private let message: IEndpointSecurityClientMessage

    private var allow: Bool = false
    private var cache: Bool = false

    public init(authorizationInterface: IAuthorizationInterface, message: IEndpointSecurityClientMessage) {
        self.message = message
        self.authorizationInterface = authorizationInterface

        super.init()
    }

    public override func main() {
        guard !isCancelled else { return }

        let request = IAuthorizationInterfaceRequest(binaryPath: message.binaryPath,
                                                     cdhash: message.cdhash,
                                                     signingId: message.signingId,
                                                     teamId: message.teamId,
                                                     isAppleSigned: message.isAppleSigned)

        if !authorizationInterface.ruleForBinary(request: request, allow: &allow, cache: &cache) {
            allow = false
            cache = false
        }
    }

    public func isAllowed() -> Bool {
        allow
    }

    public func cacheEnabled() -> Bool {
        cache
    }
}
