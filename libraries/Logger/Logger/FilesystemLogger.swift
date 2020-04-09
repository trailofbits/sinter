/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

final class FilesystemLogger: ILogger {
    let logFileURL: URL

    private static func getLogPath(logFolderPath: String) -> URL {
        let logFolderURL = URL(string: "file:///" + logFolderPath)!

        let formatter = DateFormatter()
        formatter.dateFormat = "yyy-MM-dd"

        let dateString = formatter.string(from: Date())
        let fileName = "Sinter-\(dateString).log"

        return logFolderURL.appendingPathComponent(fileName)
    }

    public init?(logFolderPath: String) {
        logFileURL = FilesystemLogger.getLogPath(logFolderPath: logFolderPath)
    }

    public func logAuthorization(message: AuthorizationLogMessage) {
        let logLine = "action=EXEC|decision=ALLOW|reason=BINARY|sha256=\(message.cdHash)|cert_sha256=?|cert_cn=?|"
            + "pid=\(String(message.pid))|ppid=\(String(message.ppid))|uid=\(String(message.uid))"
            + "|user=?|gid=\(String(message.gid))|group=?|mode=?|path=\(message.binaryPath)"
            + "|args=?|\n"

        do {
            try logLine.write(to: logFileURL,
                              atomically: true,
                              encoding: .utf8)

        } catch {
            print("\(logLine)")
        }
    }

    public func logMessage(severity: LogMessageSeverity, message: String) {
        let severityDescription: String
        switch severity {
        case LogMessageSeverity.debug:
            severityDescription = "Debug"

        case LogMessageSeverity.information:
            severityDescription = "Information"

        case LogMessageSeverity.warning:
            severityDescription = "Warning"

        case LogMessageSeverity.error:
            severityDescription = "Error"
        }

        let logLine = "severity=\(String(severityDescription))|message=\(message)\n"

        do {
            try logLine.write(to: logFileURL,
                              atomically: true,
                              encoding: .utf8)

        } catch {
            print("\(logLine)")
        }
    }
}
