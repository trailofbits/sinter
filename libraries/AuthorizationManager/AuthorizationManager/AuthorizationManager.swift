/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Cocoa
import Foundation

import CodeSigningUtils
import EndpointSecurityClient
import SignatureChecker

let logPath = "file:///var/db/sinter/"
class Logger {
    
    static var logFile: URL? {
        let logsDirectory = URL(string: logPath)
        
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        let dateString = formatter.string(from: Date())
        let fileName = "Sinter-\(dateString).log"
        return logsDirectory!.appendingPathComponent(fileName)
    }

    static func log(_ message: String) {
        guard let logFile = logFile else {
            return
        }
        //print("Logging to path: ", logFile)
        
        let formatter = DateFormatter()
        formatter.dateFormat = "'['yyyy-MM-dd'T'HH:mm:ss.SSS'Z]'"
        let timestamp = formatter.string(from: Date())
        guard let data = (timestamp + " sinter: " + message + "\n").data(using: String.Encoding.utf8)
            else { return }

        if FileManager.default.fileExists(atPath: logFile.path) {
            if let fileHandle = try? FileHandle(forWritingTo: logFile) {
                fileHandle.seekToEndOfFile()
                fileHandle.write(data)
                fileHandle.closeFile()
            }
        } else {
            do {
                // Create the log directory first if needed:
                let logsDirectory = URL(string: logPath)
                try FileManager.default.createDirectory(at: logsDirectory!, withIntermediateDirectories: true,
                                                        attributes: nil)

                // Then write the log:
                do {
                    try data.write(to: logFile, options: .atomicWrite)
                } catch (let writeError) {
                    print("Failed to write to log at \(logFile) : \(writeError)")
                }
            } catch (let createError)  {
                print("Failed to create log directory at \(logPath) : \(createError)")
            }
        }
    }
}

public class AuthorizationManager {
    var terminateExecution: Bool = false
    let terminateExecutionDq = DispatchQueue(label: "shouldTerminateDq")

    var endpointSecClient: EndpointSecurityClient
    var signatureChecker: SignatureChecker

    var authorizationCache = [String: Bool]()

    public init?() {
        if let endpointSecClient = EndpointSecurityClient() {
            self.endpointSecClient = endpointSecClient
        } else {
            return nil
        }

        if let signatureChecker = SignatureChecker() {
            self.signatureChecker = signatureChecker
        } else {
            return nil
        }
    }

    deinit {}

    public func exec() -> Bool {
        while !shouldTerminate() {
            let messageList = endpointSecClient.getMessages()
            if !messageList.isEmpty {
                signatureChecker.addMessagesToQueue(messageList: messageList)
            }

            let processedMessageList = signatureChecker.getProcessedMessages()
            for message in processedMessageList {
                if message.signatureStatus != CodeSignatureStatus.Valid {
                    endpointSecClient.processMessage(message: message, allow: false)
                    print("Automatically denying execution for binary with broken signature: ", message.binaryPath)

                } else {
                    if authorizationCache[message.binaryPath] != nil {
                        print("Automatically re-authorizing application: ", message.binaryPath)
                        let allowExecution = authorizationCache[message.binaryPath]!
                        endpointSecClient.processMessage(message: message, allow: allowExecution)

                    } else {
                        print("Automatically allowing executing for binary with valid signature: ")
                        print("     path: ", message.binaryPath)
                        print("     cdhash: ", message.cdhash)
                        print("     parent process ID: ", String(message.ppid))
                        print("     process group ID: ", String(message.gid))
                        print("     process ID: ", String(message.pid))
                        print("     user ID: ", String(message.uid))
                        print("     signing info: signing ID: ", message.signingId)
                        print("     signing info: team ID: ", message.teamId)
                        print("     is signed with Apple certificates: ", message.isAppleSigned)
                        let logLine = "action=EXEC|decision=ALLOW|reason=CERT|sha256=?|cert_sha256=?|cert_cn=?|"
                                    + "pid=\(String(message.pid))|ppid=\(String(message.ppid))|uid=\(String(message.uid))"
                                    + "|user=?|gid=\(String(message.gid))|group=?|mode=?|path=\(message.binaryPath)"
                                    + "|args=?|"
                        Logger.log(logLine)

                        authorizationCache[message.binaryPath] = true
                        endpointSecClient.processMessage(message: message,
                                                         allow: authorizationCache[message.binaryPath]!)
                    }
                }
            }
        }

        return true
    }

    public func terminate() {
        terminateExecutionDq.sync {
            self.terminateExecution = true
        }
    }

    func shouldTerminate() -> Bool {
        terminateExecutionDq.sync {
            self.terminateExecution
        }
    }
}
