/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import AuthorizationManager
import Configuration
import EndpointSecurityClient
import Logger
import MorozAuthorizationInterface
import SignatureDatabase

import Dispatch

let localConfigurationOpt = createLocalJSONConfiguration()
if localConfigurationOpt == nil {
    print("Failed to initialize the Configuration object")
    exit(EXIT_FAILURE)
}

let filesystemLoggerOpt = createFilesystemLogger(configuration: localConfigurationOpt!)
if filesystemLoggerOpt == nil {
    print("Failed to initialize the FilesystemLogger object")
    exit(EXIT_FAILURE)
}

let authorizationInterfaceOpt = createMorozAuthorizationInterface(logger: filesystemLoggerOpt!,
                                                                  configuration: localConfigurationOpt!)

if authorizationInterfaceOpt == nil {
    filesystemLoggerOpt!.logMessage(severity: LogMessageSeverity.error,
                                    message: "Failed to initialize the AuthorizationInterface object")

    exit(EXIT_FAILURE)
}

let signatureDatabaseOpt = createSignatureDatabase(logger: filesystemLoggerOpt!,
                                                   concurrentOperationCount: 4)

if signatureDatabaseOpt == nil {
    filesystemLoggerOpt!.logMessage(severity: LogMessageSeverity.error,
                                    message: "Failed to initialize the SignatureDatabase object")

    exit(EXIT_FAILURE)
}

let endpointSecurityClientOpt = createEndpointSecurityClient(logger: filesystemLoggerOpt!)
if endpointSecurityClientOpt == nil {
    filesystemLoggerOpt!.logMessage(severity: LogMessageSeverity.error,
                                    message: "Failed to initialize the EndpointSecurityClient object")

    exit(EXIT_FAILURE)
}

let authorizationManagerOpt = createAuthorizationManager(authorizationInterface: authorizationInterfaceOpt!,
                                                         signatureDatabase: signatureDatabaseOpt!,
                                                         endpointSecurityClient: endpointSecurityClientOpt!,
                                                         logger: filesystemLoggerOpt!,
                                                         concurrentOperationCount: 4)

if authorizationManagerOpt == nil {
    filesystemLoggerOpt!.logMessage(severity: LogMessageSeverity.error,
                                    message: "Failed to initialize the AuthorizationManager object")

    exit(EXIT_FAILURE)
}

let signalHandler = DispatchSource.makeSignalSource(signal: SIGINT,
                                                    queue: .main)

signalHandler.setEventHandler {
    filesystemLoggerOpt!.logMessage(severity: LogMessageSeverity.information,
                                    message: "Terminating...")

    DispatchQueue.main.async {
        exit(EXIT_SUCCESS)
    }
}

signalHandler.resume()
signal(SIGINT, SIG_IGN)

RunLoop.current.run()
dispatchMain()
