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
import Configuration
import AuthorizationManager
import DecisionManager

var configuration: ConfigurationInterface
var authorizationManager: AuthorizationManagerInterface
var decisionManager: DecisionManagerInterface

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
var loggerPluginName = "unifiedlogging"
if let configuredLoggerPluginName = configuration.stringValue(section: "Sinter", key: "logger") {
    loggerPluginName = configuredLoggerPluginName
}

let logger: LoggerInterface
if loggerPluginName == "filesystem" {
    logger = createFilesystemLogger()

} else if loggerPluginName == "unifiedlogging" {
    logger = createUnifiedLoggingLogger()

} else {
    print("The following logger plugin is not valid: \(loggerPluginName)")
    exit(EXIT_FAILURE)
}

// The logger has been using stdout/stderr so far; pass the
// new configuration object we just created
logger.setConfiguration(configuration: configuration)

// Initialize the decision manager
if let decisionManagerPluginName = configuration.stringValue(section: "Sinter", key: "decision_manager") {
    if decisionManagerPluginName == "sync-server" {
        logger.logMessage(severity: LoggerMessageSeverity.information,
                          message: "Initializing the sync-server decision manager plugin")

        decisionManager = createRemoteDecisionManager(logger: logger,
                                                      configuration: configuration)

    } else if decisionManagerPluginName == "local" {
        logger.logMessage(severity: LoggerMessageSeverity.information,
                          message: "Initializing the local decision manager plugin")

        decisionManager = createLocalDecisionManager(logger: logger,
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

// Initialize the AuthorizationManager
let authorizationManagerExp = createAuthorizationManager(configuration: configuration,
                                                         logger: logger,
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
