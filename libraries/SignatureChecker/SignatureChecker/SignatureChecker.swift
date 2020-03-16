/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import CodeSigningUtils
import Dispatch
import EndpointSecurityClient

public class SignatureChecker {
    var shouldTerminate: Bool = false

    var messageList = [EndpointSecurityClientMessage]()
    let messageListDq = DispatchQueue(label: "SignatureChecker_message_list")
    let messageListSem = DispatchSemaphore(value: 0)

    var processedMessageList = [EndpointSecurityClientMessage]()
    let processedMessageListDq = DispatchQueue(label: "SignatureChecker_processed_message_list")
    let processedMessageListSem = DispatchSemaphore(value: 0)

    var codeSignatureCache = [String: CodeSignatureStatus]()

    public init?() {
        if !initializeCache() {
            return nil
        }

        DispatchQueue.global(qos: .userInteractive).async(execute: processMessageQueue)
    }

    deinit {
        // Wait for the async function to terminate?
        terminate()
    }

    public func addMessagesToQueue(messageList: [EndpointSecurityClientMessage]) {
        if messageList.isEmpty {
            return
        }

        messageListDq.sync {
            self.messageList.append(contentsOf: messageList)
            self.messageListSem.signal()
        }
    }

    public func terminate() {
        shouldTerminate = true
    }

    public func getProcessedMessages() -> [EndpointSecurityClientMessage] {
        if processedMessageListSem.wait(timeout: .now() + 5) != .success {
            return [EndpointSecurityClientMessage]()
        }

        var processedMessageList = [EndpointSecurityClientMessage]()
        processedMessageListDq.sync {
            processedMessageList = self.processedMessageList
            self.processedMessageList = [EndpointSecurityClientMessage]()
        }

        return processedMessageList
    }

    func initializeCache() -> Bool {
        let initialFolderList: [String] = ["/bin", "/usr/bin", "/usr/libexec",
                                           "/Applications", "/Applications/Utilities",
                                           "/Applications/Xcode.app/Contents/Developer/usr/bin",
                                           "/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core"]

        let fileManager = FileManager.default

        print("Initializing signature cache")
        for folderPath in initialFolderList {
            let folderURL: URL? = URL(fileURLWithPath: folderPath)
            if folderURL == nil {
                continue
            }

            do {
                print(" >", folderPath)
                let fileURLList = try fileManager.contentsOfDirectory(at: folderURL!, includingPropertiesForKeys: nil)

                for fileURL in fileURLList {
                    let signatureStatus = checkCodeSignature(path: fileURL.absoluteString)
                    codeSignatureCache[fileURL.absoluteString] = signatureStatus
                }

            } catch {}
        }

        return true
    }

    func processMessageQueue() {
        shouldTerminate = false

        while !shouldTerminate {
            if messageListSem.wait(timeout: .now() + 5) != .success {
                continue
            }

            var messageList = [EndpointSecurityClientMessage]()
            messageListDq.sync {
                messageList = self.messageList
                self.messageList = [EndpointSecurityClientMessage]()
            }

            var processedMessageList = [EndpointSecurityClientMessage]()

            // TODO: implement a thread pool to run the signature checks
            for var message in messageList {
                var signatureStatus: CodeSignatureStatus
                if self.codeSignatureCache[message.binaryPath] != nil {
                    signatureStatus = self.codeSignatureCache[message.binaryPath]!
                } else {
                    signatureStatus = checkCodeSignature(path: message.binaryPath)
                    self.codeSignatureCache[message.binaryPath] = signatureStatus
                }

                message.signatureStatus = signatureStatus
                processedMessageList.append(message)
            }

            processedMessageListDq.sync {
                self.processedMessageList.append(contentsOf: processedMessageList)
                processedMessageList = [EndpointSecurityClientMessage]()

                self.processedMessageListSem.signal()
            }
        }
    }
}
