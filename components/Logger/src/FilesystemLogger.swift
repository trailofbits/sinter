/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Configuration
import Darwin

fileprivate let defaultLogFilePath = "/var/log/sinter.log"
fileprivate let dispatchQueue = DispatchQueue(label: "com.trailofbits.sinter.filesystem-logger")

final class FilesystemLoggerContext {
    var logFileURL = URL(fileURLWithPath: "")
}

final class FilesystemLogger: LoggerInterface, ConfigurationSubscriberInterface {
    var context = FilesystemLoggerContext()

    func onConfigurationChange(configuration: ConfigurationInterface) {
        dispatchQueue.sync {
            FilesystemLogger.readConfiguration(context: &context,
                                               configuration: configuration)
        }
    }

    func setConfiguration(configuration: ConfigurationInterface) {
        configuration.subscribe(subscriber: self)
    }

    func logMessage(severity: LoggerMessageSeverity, message: String) {
        if !FilesystemLogger.logMessage(context: context,
                                        severity: severity,
                                        message: message) {

            printErrorMessage(message: "Failed to write to the log file")
            print("\(severity): \(message)")
        }
    }
    
    private func printErrorMessage(message: String) {
        fputs("\(message)\n", stderr)
    }

    static func readConfiguration(context: inout FilesystemLoggerContext,
                                  configuration: ConfigurationInterface) {

        var newLogFilePath: String
        if let logFilePath = configuration.stringValue(section: "Sinter",
                                                       key: "log_file_path") {
            newLogFilePath = logFilePath

        } else {
            newLogFilePath = defaultLogFilePath
        }
        
        context.logFileURL = URL(fileURLWithPath: newLogFilePath)
    }

    static func generateLogMessage(severity: LoggerMessageSeverity,
                                   message: String) -> String {

        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MMM-dd HH:mm:ss"

        let timestamp = dateFormatter.string(from: Date())

        return String(format: "{ \"timestamp\": \"\(timestamp)\", \"type\": \"message\", \"severity\": \"\(severity)\", \"message\": \"\(message)\" }\n")
    }
    
    static func logMessage(context: FilesystemLoggerContext,
                           severity: LoggerMessageSeverity,
                           message: String) -> Bool {

        let message = FilesystemLogger.generateLogMessage(severity: severity,
                                                          message: message)

        var succeeded = false

        dispatchQueue.sync {
            if let fileHandle = try? FileHandle(forWritingTo: context.logFileURL) {
                fileHandle.seekToEndOfFile()

                let messageData = message.data(using: .utf8)!
                fileHandle.write(messageData)

                fileHandle.closeFile()

                succeeded = true

            } else {
                do {
                    try message.write(to: context.logFileURL,
                                      atomically: true,
                                      encoding: .utf8)

                    succeeded = true

                } catch {
                }
            }
        }

        return succeeded
    }
}
