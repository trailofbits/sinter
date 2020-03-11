/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

import Dispatch
import CodeSigningUtils

class SignatureChecker {
  var should_terminate: Bool = false

  var message_list = [EndpointSecurityMessage]()
  let message_list_dq = DispatchQueue(label: "SignatureChecker_message_list")
  let message_list_sem = DispatchSemaphore(value: 0)

  var processed_message_list = [EndpointSecurityMessage]()
  let processed_message_list_dq = DispatchQueue(label: "SignatureChecker_processed_message_list")
  let processed_message_list_sem = DispatchSemaphore(value: 0)

  var code_signature_cache = [String: CodeSignatureStatus]()

  init?() {
    DispatchQueue.global(qos: .background).async(execute: processMessageQueue)
  }

  deinit {
    // Wait for the async function to terminate?
    terminate()
  }

  func addMessagesToQueue(message_list: [EndpointSecurityMessage]) {
    if (message_list.isEmpty) {
      return
    }

    self.message_list_dq.sync {
      self.message_list.append(contentsOf: message_list)
      self.message_list_sem.signal()
    }
  }

  func processMessageQueue() {
    self.should_terminate = false

    while (!self.should_terminate) {
      if (self.message_list_sem.wait(timeout: .now() + 5) != .success) {
        continue
      }

      var message_list = [EndpointSecurityMessage]()
      self.message_list_dq.sync {
        message_list = self.message_list
        self.message_list = [EndpointSecurityMessage]()
      }

      var processed_message_list = [EndpointSecurityMessage]()

      for var message in message_list {
        var signature_status: CodeSignatureStatus
        if (self.code_signature_cache[message.binary_path] != nil) {
          print("Restoring from cache: ", message.binary_path)
          signature_status = self.code_signature_cache[message.binary_path]!
        } else {
          signature_status = checkCodeSignature(path: message.binary_path)
          self.code_signature_cache[message.binary_path] = signature_status
        }

        message.signature_status = signature_status
        processed_message_list.append(message)
      }

      self.processed_message_list_dq.sync {
        self.processed_message_list.append(contentsOf: processed_message_list)
        processed_message_list = [EndpointSecurityMessage]()

        self.processed_message_list_sem.signal()
      }
    }
  }

  func getProcessedMessages() -> [EndpointSecurityMessage] {
    if (self.processed_message_list_sem.wait(timeout: .now() + 5) != .success) {
      return [EndpointSecurityMessage]()
    }

    var processed_message_list = [EndpointSecurityMessage]()
    self.processed_message_list_dq.sync {
      processed_message_list = self.processed_message_list
      self.processed_message_list = [EndpointSecurityMessage]()
    }

    return processed_message_list
  }

  func terminate() {
    self.should_terminate = true
  }
}

