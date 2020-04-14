/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Dispatch
import Foundation

import EndpointSecurityClient
import FilesystemLogger
import InMemorySignatureDatabase
import JSONConfiguration
import LibSinter
import LocalDecisionManager
import SyncServerDecisionManager

var configuration: ConfigurationInterface
var logger: LoggerInterface
var signatureDatabase: SignatureDatabaseInterface
var authorizationManager: AuthorizationManagerInterface
var decisionManager: DecisionManagerInterface

// Determine which decision manager plugin we should load
let syncServerFlag = "--decision-manager=sync-server"
let localRulesFlag = "--decision-manager=local"

print("Rule database options:")
print(" > sync-server: \(syncServerFlag) (default)")
print(" > Local rule database-server: \(localRulesFlag)\n")

var useSyncServerDecisionManager = CommandLine.arguments.contains(syncServerFlag)
let useLocalDecisionManager = CommandLine.arguments.contains(localRulesFlag)

if useSyncServerDecisionManager, useLocalDecisionManager {
    print("Please only use '\(syncServerFlag)' or '\(localRulesFlag)'")
    exit(EXIT_FAILURE)
}

if !useLocalDecisionManager {
    useSyncServerDecisionManager = true
}

// Initialize the configuration
let configurationExp = createJSONConfiguration()
switch configurationExp {
case let .success(obj):
    configuration = obj

case let .failure(error):
    print("Failed to create the JSONConfiguration object: \(error)")
    exit(EXIT_FAILURE)
}

// Initialize the logger
let loggerExp = createFilesystemLogger(configuration: configuration)
switch loggerExp {
case let .success(obj):
    logger = obj

case let .failure(error):
    print("Failed to create the FilesytemLogger object: \(error)")
    exit(EXIT_FAILURE)
}

logger.logMessage(severity: LoggerMessageSeverity.information, message: "Initializing")

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

if useSyncServerDecisionManager {
    print("Using sync-server")
    decisionManagerExp = createSyncServerDecisionManager(logger: logger,
                                                         configuration: configuration)
} else {
    print("Using local rule database")
    decisionManagerExp = createLocalDecisionManager(logger: logger,
                                                    configuration: configuration)
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
