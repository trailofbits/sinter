/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation
import NotificationService
import Configuration
import Logger
import DecisionManager
import EndpointSecurityClient

struct ApplicationDirectorySettings {
    public var allowMisplacedApplications = true
    public var allowedApplicationDirectories = [String]()
}

final class AuthorizationManager: AuthorizationManagerInterface,
                                          ConfigurationSubscriberInterface {

    private let logger: LoggerInterface
    private let decisionManager: DecisionManagerInterface

    private var endpointSecurityOpt: EndpointSecurityInterface? = nil
    private let notificationClient: NotificationClientInterface
    private let signatureDatabase: SignatureDatabase
    private var applicationDirectorySettings = ApplicationDirectorySettings()

    private init(configuration: ConfigurationInterface,
                 logger: LoggerInterface,
                 decisionManager: DecisionManagerInterface,
                 endpointSecurityFactory: EndpointSecurityInterfaceFactory) throws {

        self.logger = logger
        self.decisionManager = decisionManager

        signatureDatabase = SignatureDatabase(logger: self.logger)
        notificationClient = createNotificationClient()

        let endpointSecurityExp = endpointSecurityFactory(logger,
                                                          configuration,
                                                          onEndpointSecurityMessage)

        switch endpointSecurityExp {
        case let .success(obj):
            endpointSecurityOpt = obj

        case let .failure(error):
            self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                   message: "The EndpointSecurity factory returned an error: \(error)")

            throw AuthorizationManagerError.endpointSecurityFactoryError
        }

        configuration.subscribe(subscriber: self)
    }

    func onConfigurationChange(configuration: ConfigurationInterface) {
        applicationDirectorySettings.allowedApplicationDirectories = [String]()

        if let allowedApplicationDirectories = configuration.stringList(section: "Sinter",
                                                                        key: "allowed_application_directories") {

            for var path in allowedApplicationDirectories {
                if path.isEmpty {
                    continue
                }

                if path.last! != "/" {
                    path += "/"
                }

                applicationDirectorySettings.allowedApplicationDirectories.append(path)
            }
        }

        if let allowMisplacedApplications = configuration.booleanValue(section: "Sinter",
                                                                       key: "allow_misplaced_applications") {

            applicationDirectorySettings.allowMisplacedApplications = allowMisplacedApplications
        } else {
            applicationDirectorySettings.allowMisplacedApplications = false
        }

        logger.logMessage(severity: LoggerMessageSeverity.information,
                          message: "Deleting the cache")

        _ = endpointSecurityOpt!.invalidateCache()
        signatureDatabase.invalidateCache()
    }

    private func onEndpointSecurityMessage(message: EndpointSecurityMessage) {
        switch message {
        case let .ExecAuthorization(execAuthorization):
            var isMisplaced = false
            let allowed = AuthorizationManager.isApplicationPathAllowed(applicationDirectorySettings: applicationDirectorySettings,
                                                                        binaryPath: execAuthorization.binaryPath,
                                                                        isMisplaced: &isMisplaced)

            if isMisplaced {
                logger.logMessage(severity: .error,
                                  message: "The following application is not being started from a valid path: \(execAuthorization.binaryPath)")
            }

            if !allowed {
                DispatchQueue.main.async {
                    _ = self.endpointSecurityOpt!.setAuthorization(identifier: execAuthorization.identifier,
                                                                   allow: false,
                                                                   cache: true)
                }

                let message = "Blocked: \(execAuthorization.binaryPath) (invalid path)"

                self.notificationClient.showNotification(message: message)
                self.logger.logMessage(severity: LoggerMessageSeverity.information,
                                       message: message)

            } else {
                signatureDatabase.checkSignatureFor(message: execAuthorization,
                                                    block: signatureDatabaseCallback)
            }

        case let .ExecInvalidationNotification(execInvalidationNotification):
            let logMessage: String
            let notificationMessage: String

            switch execInvalidationNotification.reason {
            case .applicationChanged:
                logMessage = "'\(execInvalidationNotification.binaryPath)' has been denied execution because the application has been changed on disk"
                notificationMessage = "Denied '\(execInvalidationNotification.binaryPath)' (application changed)"

            case .expired:
                logMessage = "The authorization request for '\(execInvalidationNotification.binaryPath)' has taken too long and has expired"

                notificationMessage = "Authorization request expired: '\(execInvalidationNotification.binaryPath)'"
            }

            logger.logMessage(severity: LoggerMessageSeverity.warning,
                              message: logMessage)

            notificationClient.showNotification(message: notificationMessage)

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

    private func signatureDatabaseCallback(message: EndpointSecurityExecAuthorization,
                                           result: SignatureDatabaseResult) {

        switch result {
        case SignatureDatabaseResult.Failed:
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "Failed to validate the code signature for '\(message.binaryPath)'")

        case SignatureDatabaseResult.Invalid:
            logger.logMessage(severity: LoggerMessageSeverity.information,
                              message: "Invalid code signature for '\(message.binaryPath)'")

        case SignatureDatabaseResult.NotSigned:
            logger.logMessage(severity: LoggerMessageSeverity.information,
                              message: "The following application is not signed '\(message.binaryPath)'")

        case SignatureDatabaseResult.Valid:
            ()
        }

        let request = DecisionManagerRequest(binaryPath: message.binaryPath,
                                             codeDirectoryHash: message.codeDirectoryHash,
                                             signingIdentifier: message.signingIdentifier,
                                             teamIdentifier: message.teamIdentifier,
                                             binaryType: message.binaryType)

        var allow = false
        var cache = false
        decisionManager.processRequest(request: request,
                                       allow: &allow,
                                       cache: &cache,
                                       signatureCheckResult: result)

        _ = endpointSecurityOpt!.setAuthorization(identifier: message.identifier,
                                                  allow: allow,
                                                  cache: cache)

        if allow {
             logger.logMessage(severity: LoggerMessageSeverity.information,
                              message: "Allowed: '\(message.binaryPath)'")

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.information,
                             message: "Blocked: '\(message.binaryPath)'")

            notificationClient.showNotification(message: "Blocked: \(message.binaryPath)")
        }
    }

    static func create(configuration: ConfigurationInterface,
                       logger: LoggerInterface,
                       decisionManager: DecisionManagerInterface,
                       endpointSecurityFactory: EndpointSecurityInterfaceFactory) -> Result<AuthorizationManagerInterface, Error> {
        Result<AuthorizationManagerInterface, Error> { try AuthorizationManager(configuration: configuration,
                                                                                logger: logger,
                                                                                decisionManager: decisionManager,
                                                                                endpointSecurityFactory: endpointSecurityFactory) }
    }

    static func isApplicationMisplaced(applicationDirectorySettings: ApplicationDirectorySettings,
                                       binaryPath: String) -> Bool {

        if applicationDirectorySettings.allowedApplicationDirectories.isEmpty {
            return false
        }

        for var allowedDirectory in applicationDirectorySettings.allowedApplicationDirectories {
            if allowedDirectory.isEmpty {
                continue
            }

            if allowedDirectory.last! != "/" {
                allowedDirectory += "/"
            }

            if binaryPath.starts(with: allowedDirectory) {
                return false
            }
        }

        return true
    }
    
    static func isApplicationPathAllowed(applicationDirectorySettings: ApplicationDirectorySettings,
                                         binaryPath: String,
                                         isMisplaced: inout Bool) -> Bool {

        isMisplaced = isApplicationMisplaced(applicationDirectorySettings: applicationDirectorySettings,
                                             binaryPath: binaryPath)

        if isMisplaced {
            return applicationDirectorySettings.allowMisplacedApplications
        }
        
        return true
    }
}

public func createAuthorizationManager(configuration: ConfigurationInterface,
                                       logger: LoggerInterface,
                                       decisionManager: DecisionManagerInterface,
                                       endpointSecurityFactory: EndpointSecurityInterfaceFactory) -> Result<AuthorizationManagerInterface, Error> {

    AuthorizationManager.create(configuration: configuration,
                                logger: logger,
                                decisionManager: decisionManager,
                                endpointSecurityFactory: endpointSecurityFactory)
}
