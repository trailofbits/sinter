/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import AuthorizationManager
import Cocoa
import Dispatch

print("Initializing the Authorization Manager")
let authorizationManager: AuthorizationManager? = AuthorizationManager()
if authorizationManager == nil {
    print("Failed to initialize the AuthorizationManager object")
    exit(EXIT_FAILURE)
}

print("Installing signal handler")
let signalHandler = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
signalHandler.setEventHandler {
    authorizationManager!.terminate()
}

signalHandler.resume()
signal(SIGINT, SIG_IGN)

print("Starting the Authorization Manager")
DispatchQueue.global(qos: .userInteractive).async {
    let exit_status = authorizationManager!.exec() ? EXIT_SUCCESS : EXIT_FAILURE

    DispatchQueue.main.async {
        print("Terminating with status ", exit_status)
        exit(exit_status)
    }
}

dispatchMain()
