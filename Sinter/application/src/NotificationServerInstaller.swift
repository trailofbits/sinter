/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

fileprivate let launchConfigurationPath = "/Library/LaunchAgents/com.trailofbits.sinter.notification-server.plist"

fileprivate let launchdConfigurationData = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.trailofbits.sinter.notification-server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/Sinter.app/Contents/XPCServices/notification-server.app/Contents/MacOS/notification-server</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""

func installNotificationServer() -> Bool {
    do {
        try launchdConfigurationData.write(toFile: launchConfigurationPath,
                                           atomically: true,
                                           encoding: .utf8)

        return true

    } catch {
        print("Failed to install the launchd configuration file: \(error)")
        return false
    }
}

func uninstallNotificationServer() -> Bool {
    do {
        let fileManager = FileManager.default
        try fileManager.removeItem(atPath: launchConfigurationPath)

        return true

    } catch {
        print("Failed to uninstall the launchd configuration file: \(error)")
        return false
    }
}

func startNotificationServer() {
    do {
        var process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["load",
                             launchConfigurationPath]

        try process.run()
        process.waitUntilExit()

        process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["start", "com.trailofbits.sinter.notification-server"]

        try process.run()
        process.waitUntilExit()

    } catch {
        print("Failed to start the launchctl process: \(error)")
    }
}

func stopNotificationServer() {
    do {
        var process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["stop", "com.trailofbits.sinter.notification-server"]

        try process.run()
        process.waitUntilExit()

        process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["unload",
                             launchConfigurationPath]

        try process.run()
        process.waitUntilExit()

    } catch {
        print("Failed to start the launchctl process: \(error)")
    }
}
