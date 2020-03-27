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

                        authorizationCache[message.binaryPath] = true
                        endpointSecClient.processMessage(message: message, allow: authorizationCache[message.binaryPath]!)
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
