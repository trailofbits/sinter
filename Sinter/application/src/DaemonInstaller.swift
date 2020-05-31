/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

fileprivate let launchConfigurationPath = "/Library/LaunchDaemons/com.trailofbits.sinter.plist"

fileprivate let launchdConfigurationData = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	  <key>StandardErrorPath</key>
	  <string>/var/log/sinter_stderr.log</string>
	  <key>StandardOutPath</key>
	  <string>/var/log/sinter_stdout.log</string>
	  <key>Label</key>
	  <string>com.trailofbits.sinter</string>
	  <key>ProgramArguments</key>
	  <array>
        <string>/Applications/Sinter.app/Contents/Library/SystemExtensions/com.trailofbits.sinter.daemon.systemextension/Contents/MacOS/com.trailofbits.sinter.daemon</string>
	  </array>
	  <key>RunAtLoad</key>
    <true/>
	  <key>KeepAlive</key>
	  <true/>
</dict>
</plist>

"""

func installDaemon() -> Bool {
    do {
        try launchdConfigurationData.write(toFile: launchConfigurationPath,
                                           atomically: true,
                                           encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["load",
                             launchConfigurationPath]

        try process.run()
        process.waitUntilExit()

        return true

    } catch {
        print("Failed to install the launchd configuration file: \(error)")
        return false
    }
}

func uninstallDaemon() -> Bool {
    do {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["unload",
                             launchConfigurationPath]

        try process.run()
        process.waitUntilExit()

        let fileManager = FileManager.default
        try fileManager.removeItem(atPath: launchConfigurationPath)

        return true

    } catch {
        print("Failed to uninstall the launchd configuration file: \(error)")
        return false
    }
}

func startDaemon() -> Bool {
    do {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["start", "com.trailofbits.sinter"]

        try process.run()
        process.waitUntilExit()

        return true

    } catch {
        print("Failed to start the launchctl process: \(error)")
        return false
    }
}

func stopDaemon() -> Bool {
    do {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["stop", "com.trailofbits.sinter"]

        try process.run()
        process.waitUntilExit()

        return true

    } catch {
        print("Failed to start the launchctl process: \(error)")
        return false
    }
}
