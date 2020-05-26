/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Dispatch
import Foundation

import EndpointSecurityClient
import Logger
import InMemorySignatureDatabase
import Configuration
import AuthorizationManager
import LocalDecisionManager
import SyncServerDecisionManager

var configuration: ConfigurationInterface
var signatureDatabase: SignatureDatabaseInterface
var authorizationManager: AuthorizationManagerInterface
var decisionManager: DecisionManagerInterface

// Initialize the logger
let logger = createFilesystemLogger()

// Initialize the configuration
let configurationExp = createJSONConfiguration()
switch configurationExp {
case let .success(obj):
    configuration = obj

case let .failure(error):
    print("Failed to create the JSONConfiguration object: \(error)")
    exit(EXIT_FAILURE)
}

// The logger has been using stdout/stderr so far; pass the
// new configuration object we just created
logger.setConfiguration(configuration: configuration)

// Initialize the SignatureDatabase
let signatureDatabaseExp = createInMemorySignatureDatabase()
switch signatureDatabaseExp {
case let .success(obj):
    signatureDatabase = obj

case let .failure(error):
    print("Failed to create the SignatureDatabase object: \(error)")
    exit(EXIT_FAILURE)
}

// Initialize the DecisionManager
var decisionManagerExp: Result<DecisionManagerInterface, Error>

// Initialize the decision manager
if let decisionManagerPluginName = configuration.stringValue(section: "Sinter", key: "decision_manager") {
    if decisionManagerPluginName == "sync-server" {
        logger.logMessage(severity: LoggerMessageSeverity.information,
                          message: "Initializing the sync-server decision manager plugin")

        decisionManagerExp = createSyncServerDecisionManager(logger: logger,
                                                             configuration: configuration)

    } else if decisionManagerPluginName == "local" {
        logger.logMessage(severity: LoggerMessageSeverity.information,
                          message: "Initializing the local decision manager plugin")

        decisionManagerExp = createLocalDecisionManager(logger: logger,
                                                        configuration: configuration)

    } else {
        logger.logMessage(severity: LoggerMessageSeverity.error,
                          message: "Invalid 'decision_manager' plugin name in the 'Sinter' configuration section")

        exit(EXIT_FAILURE)
    }

} else {
    logger.logMessage(severity: LoggerMessageSeverity.error,
                      message: "The configuration file does not contain the Sinter::decision_manager key")

    exit(EXIT_FAILURE)
}

switch decisionManagerExp {
case let .success(obj):
    decisionManager = obj

case let .failure(error):
    print("Failed to create the DecisionManager object: \(error)")
    exit(EXIT_FAILURE)
}

// Initialize the AuthorizationManager
let authorizationManagerExp = createAuthorizationManager(configuration: configuration,
                                                         logger: logger,
                                                         signatureDatabase: signatureDatabase,
                                                         decisionManager: decisionManager,
                                                         endpointSecurityFactory: createEndpointSecurityClient)

switch authorizationManagerExp {
case let .success(obj):
    authorizationManager = obj

case let .failure(error):
    print("Failed to create the AuthorizationManager object: \(error)")
    exit(EXIT_FAILURE)
}

// Install a signal handler to handle CTRL+C
let signalHandler = DispatchSource.makeSignalSource(signal: SIGINT,
                                                    queue: .main)

signalHandler.setEventHandler {
    DispatchQueue.main.async {
        exit(EXIT_SUCCESS)
    }
}

signalHandler.resume()
signal(SIGINT, SIG_IGN)

// Run the event loops
RunLoop.current.run()
dispatchMain()
