/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

import Dispatch
import CodeSigningUtils

class SignatureChecker {
  var shouldTerminate: Bool = false

  var messageList = [EndpointSecurityMessage]()
  let messageListDq = DispatchQueue(label: "SignatureChecker_message_list")
  let messageListSem = DispatchSemaphore(value: 0)

  var processedMessageList = [EndpointSecurityMessage]()
  let processedMessageListDq = DispatchQueue(label: "SignatureChecker_processed_message_list")
  let processedMessageListSem = DispatchSemaphore(value: 0)

  var codeSignatureCache = [String: CodeSignatureStatus]()

  init?() {
    DispatchQueue.global(qos: .background).async(execute: processMessageQueue)
  }

  deinit {
    // Wait for the async function to terminate?
    terminate()
  }

  func addMessagesToQueue(messageList: [EndpointSecurityMessage]) {
    if messageList.isEmpty {
      return
    }

    self.messageListDq.sync {
      self.messageList.append(contentsOf: messageList)
      self.messageListSem.signal()
    }
  }

  func processMessageQueue() {
    self.shouldTerminate = false

    while !self.shouldTerminate {
      if self.messageListSem.wait(timeout: .now() + 5) != .success {
        continue
      }

      var messageList = [EndpointSecurityMessage]()
      self.messageListDq.sync {
        messageList = self.messageList
        self.messageList = [EndpointSecurityMessage]()
      }

      var processedMessageList = [EndpointSecurityMessage]()

      for var message in messageList {
        var signatureStatus: CodeSignatureStatus
        if self.codeSignatureCache[message.binaryPath] != nil {
          print("Restoring from cache: ", message.binaryPath)
          signatureStatus = self.codeSignatureCache[message.binaryPath]!
        } else {
          signatureStatus = checkCodeSignature(path: message.binaryPath)
          self.codeSignatureCache[message.binaryPath] = signatureStatus
        }

        message.signatureStatus = signatureStatus
        processedMessageList.append(message)
      }

      self.processedMessageListDq.sync {
        self.processedMessageList.append(contentsOf: processedMessageList)
        processedMessageList = [EndpointSecurityMessage]()

        self.processedMessageListSem.signal()
      }
    }
  }

  func getProcessedMessages() -> [EndpointSecurityMessage] {
    if self.processedMessageListSem.wait(timeout: .now() + 5) != .success {
      return [EndpointSecurityMessage]()
    }

    var processedMessageList = [EndpointSecurityMessage]()
    self.processedMessageListDq.sync {
      processedMessageList = self.processedMessageList
      self.processedMessageList = [EndpointSecurityMessage]()
    }

    return processedMessageList
  }

  func terminate() {
    self.shouldTerminate = true
  }
}
