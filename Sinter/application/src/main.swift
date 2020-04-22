/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Cocoa

import JSONConfiguration
import AuthorizationManager

// Do not start if the path is not right; system extensions can't even be
// registered if they are not under /Applications/Bundle.app/Library/SystemExtensions
if Bundle.main.bundlePath != "/Applications/Sinter.app" {
    print("Sinter must be copied inside the /Applications folder")
    exit(EXIT_FAILURE)
}

// Initialize the configuration
let configuration: ConfigurationInterface

let configurationExp = createJSONConfiguration()
switch configurationExp {
case let .success(obj):
    configuration = obj

case let .failure(error):
    print("Failed to create the JSONConfiguration object: \(error)")
    exit(EXIT_FAILURE)
}

let systemExtensionInstaller: SystemExtensionInstaller

if CommandLine.arguments.contains("--install-system-extension") {
    print("Installing the system extension")
    systemExtensionInstaller = SystemExtensionInstaller(operation: SystemExtensionInstallerOperation.install)

} else if CommandLine.arguments.contains("--uninstall-system-extension") {
    print("Uninstalling the system extension")
    systemExtensionInstaller = SystemExtensionInstaller(operation: SystemExtensionInstallerOperation.uninstall)

} else if CommandLine.arguments.contains("--install-notification-server") {
    if installNotificationServer() {
        print("The notification server has been installed")
        exit(EXIT_SUCCESS)
    } else {
        print("Failed to install the notification server")
        exit(EXIT_FAILURE)
    }

} else if CommandLine.arguments.contains("--uninstall-notification-server") {
    if uninstallNotificationServer() {
        print("The notification server has been uninstalled")
        exit(EXIT_SUCCESS)
    } else {
        print("Failed to uninstall the notification server")
        exit(EXIT_FAILURE)
    }

} else if CommandLine.arguments.contains("--start-notification-server") {
    startNotificationServer()
    exit(EXIT_SUCCESS)

} else if CommandLine.arguments.contains("--stop-notification-server") {
    stopNotificationServer()
    exit(EXIT_SUCCESS)

} else {
    let alert = NSAlert()
    alert.messageText = "Sinter"
    alert.informativeText = "This program runs in background as a service, and does not need to be manually started"
    alert.runModal()

    exit(EXIT_SUCCESS)
}

RunLoop.current.run()
dispatchMain()
