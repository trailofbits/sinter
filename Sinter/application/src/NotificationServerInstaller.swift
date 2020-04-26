/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

private let launchConfigurationPath = "/Library/LaunchAgents/com.trailofbits.SinterNotificationServer.plist"

private let launchdConfigurationData = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.trailofbits.SinterNotificationServer</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/Sinter.app/Contents/XPCServices/SinterNotificationServer.app/Contents/MacOS/SinterNotificationServer</string>
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
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["load",
                             "-w",
                             launchConfigurationPath]

        try process.run()

    } catch {
        print("Failed to start the launchctl process: \(error)")
    }
}

func stopNotificationServer() {
    do {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["unload",
                             "-w",
                             launchConfigurationPath]

        try process.run()

    } catch {
        print("Failed to start the launchctl process: \(error)")
    }
}
