/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import AuthorizationManager
import EndpointSecurityClient
import Logger
import MorozAuthorizationInterface
import SignatureDatabase

import Dispatch

let filesystemLogger = createFilesystemLogger(logFolderPath: "/var/log/sinter")
if filesystemLogger == nil {
    print("Failed to initialize the FilesystemLogger object")
    exit(EXIT_FAILURE)
}

let authorizationInterface = createMorozAuthorizationInterface(logger: filesystemLogger!)
if authorizationInterface == nil {
    print("Failed to initialize the AuthorizationInterface object")
    exit(EXIT_FAILURE)
}

let signatureDatabase = createSignatureDatabase(concurrentOperationCount: 4)
if signatureDatabase == nil {
    print("Failed to initialize the SignatureDatabase object")
    exit(EXIT_FAILURE)
}

let endpointSecurityClientOpt = createEndpointSecurityClient()
if endpointSecurityClientOpt == nil {
    print("Failed to initialize the EndpointSecurityClient object")
    exit(EXIT_FAILURE)
}

let authorizationManager = createAuthorizationManager(authorizationInterface: authorizationInterface!,
                                                      signatureDatabase: signatureDatabase!,
                                                      endpointSecurityClient: endpointSecurityClientOpt!,
                                                      logger: filesystemLogger!,
                                                      concurrentOperationCount: 4)

if authorizationManager == nil {
    print("Failed to initialize the AuthorizationManager object")
    exit(EXIT_FAILURE)
}

let signalHandler = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
signalHandler.setEventHandler {
    print("Terminating...")

    DispatchQueue.main.async {
        exit(EXIT_SUCCESS)
    }
}

signalHandler.resume()
signal(SIGINT, SIG_IGN)

// This will not work: check out the log with: sudo log stream
import UserNotifications
let center = UNUserNotificationCenter.current()
center.requestAuthorization(options: [.alert, .badge, .sound]) { granted, error in
    if granted {
        print("Access to UserNotifications has been granted")
    } else {
        print("Access to UserNotifications has *NOT* been granted:", error!)
    }
}

dispatchMain()
