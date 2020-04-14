/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

private final class AuthorizationManager: AuthorizationManagerInterface {
    let configuration: ConfigurationInterface
    let logger: LoggerInterface
    let signatureDatabase: SignatureDatabaseInterface
    let decisionManager: DecisionManagerInterface
    var endpointSecurityOpt: EndpointSecurityInterface?

    private let operationQueue = OperationQueue()

    private init(configuration: ConfigurationInterface,
                 logger: LoggerInterface,
                 signatureDatabase: SignatureDatabaseInterface,
                 decisionManager: DecisionManagerInterface,
                 endpointSecurityFactory: EndpointSecurityInterfaceFactory) throws {
        self.configuration = configuration
        self.logger = logger
        self.signatureDatabase = signatureDatabase
        self.decisionManager = decisionManager

        // Use the factory function we have been given to create the
        // EndpointSecurity client
        let endpointSecurityExp = endpointSecurityFactory(logger,
                                                          onEndpointSecurityMessage)

        switch endpointSecurityExp {
        case let .success(obj):
            endpointSecurityOpt = obj

        case let .failure(error):
            self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                   message: "The EndpointSecurity factory returned an error: \(error)")

            throw AuthorizationManagerError.endpointSecurityFactoryError
        }

        // Initialize the operation queue according to the online processor count
        let onlineProcessorCount = sysconf(CInt(_SC_NPROCESSORS_ONLN))
        operationQueue.maxConcurrentOperationCount = onlineProcessorCount
        operationQueue.qualityOfService = .userInteractive
    }

    private func onEndpointSecurityMessage(message: EndpointSecurityMessage) {
        switch message {
        case let .ExecAuthorization(execAuthorization):
            signatureDatabase.checkSignatureFor(message: execAuthorization,
                                                block: processSignatureCheckNotification)

        case let .ExecInvalidationNotification(execInvalidationNotification):
            logger.logMessage(severity: LoggerMessageSeverity.warning,
                              message: "Binary '\(execInvalidationNotification.binaryPath)' has been changed on disk and its authorization has been denied")

        case let .ChangeNotification(changeNotification):
            if changeNotification.type == EndpointSecurityFileChangeNotificationType.unknown || changeNotification.pathList.isEmpty {
                signatureDatabase.invalidateCache()

            } else {
                for path in changeNotification.pathList {
                    signatureDatabase.invalidateCacheFor(path: path)
                }
            }
        }
    }

    private func processSignatureCheckNotification(message: EndpointSecurityExecAuthorization,
                                                   result: SignatureDatabaseResult) {
        switch result {
        case SignatureDatabaseResult.Failed:
            _ = endpointSecurityOpt!.setAuthorization(identifier: message.identifier,
                                                      allow: false,
                                                      cache: false)

            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "Failed to validate the code signature for '\(message.binaryPath)'. Execution has been denied")

        case SignatureDatabaseResult.Invalid:
            _ = endpointSecurityOpt!.setAuthorization(identifier: message.identifier,
                                                      allow: false,
                                                      cache: true)

            logger.logMessage(severity: LoggerMessageSeverity.information,
                              message: "Invalid code signature for '\(message.binaryPath)'. Execution has been denied")

        case SignatureDatabaseResult.NotSigned:
            _ = endpointSecurityOpt!.setAuthorization(identifier: message.identifier,
                                                      allow: false,
                                                      cache: true)

            logger.logMessage(severity: LoggerMessageSeverity.information,
                              message: "The following application is not signed '\(message.binaryPath)'. Execution has been denied")

        case SignatureDatabaseResult.Valid:
            let operation = AuthorizationManagerOperation(decisionManager: decisionManager,
                                                          message: message)

            operation.completionBlock = { [unowned operation, message] in
                let allow = operation.isAllowed()
                let cache = operation.cacheEnabled()

                // This operation can fail if a write notification has invalidated this
                // request inside EndpointSecurityClient
                if self.endpointSecurityOpt!.setAuthorization(identifier: message.identifier,
                                                              allow: allow,
                                                              cache: cache) {
                    var actionDescription = allow ? "allowed" : "denied"
                    actionDescription += cache ? " (cached)" : ""

                    self.logger.logMessage(severity: LoggerMessageSeverity.information,
                                           message: "The following signed application '\(message.binaryPath)' has been \(actionDescription)")
                }
            }

            operationQueue.addOperation(operation)
        }
    }

    static func create(configuration: ConfigurationInterface,
                       logger: LoggerInterface,
                       signatureDatabase: SignatureDatabaseInterface,
                       decisionManager: DecisionManagerInterface,
                       endpointSecurityFactory: EndpointSecurityInterfaceFactory) -> Result<AuthorizationManagerInterface, Error> {
        Result<AuthorizationManagerInterface, Error> { try AuthorizationManager(configuration: configuration,
                                                                                logger: logger,
                                                                                signatureDatabase: signatureDatabase,
                                                                                decisionManager: decisionManager,
                                                                                endpointSecurityFactory: endpointSecurityFactory) }
    }
}

public func createAuthorizationManager(configuration: ConfigurationInterface,
                                       logger: LoggerInterface,
                                       signatureDatabase: SignatureDatabaseInterface,
                                       decisionManager: DecisionManagerInterface,
                                       endpointSecurityFactory: EndpointSecurityInterfaceFactory) -> Result<AuthorizationManagerInterface, Error> {
    AuthorizationManager.create(configuration: configuration,
                                logger: logger,
                                signatureDatabase: signatureDatabase,
                                decisionManager: decisionManager,
                                endpointSecurityFactory: endpointSecurityFactory)
}

private final class AuthorizationManagerOperation: Operation {
    private let decisionManager: DecisionManagerInterface
    private let message: EndpointSecurityExecAuthorization

    private var allow: Bool = false
    private var cache: Bool = false

    public init(decisionManager: DecisionManagerInterface, message: EndpointSecurityExecAuthorization) {
        self.decisionManager = decisionManager
        self.message = message

        super.init()
    }

    public override func main() {
        guard !isCancelled else { return }

        let request = DecisionManagerRequest(binaryPath: message.binaryPath,
                                             codeDirectoryHash: message.codeDirectoryHash,
                                             signingIdentifier: message.signingIdentifier,
                                             teamIdentifier: message.teamIdentifier,
                                             platformBinary: message.platformBinary)

        if !decisionManager.processRequest(request: request,
                                           allow: &allow,
                                           cache: &cache) {
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
