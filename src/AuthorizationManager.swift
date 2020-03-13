/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

import Foundation
import Cocoa
import CodeSigningUtils

class AuthorizationManager {
  var endpointSec: EndpointSecurity
  var signatureChecker: SignatureChecker

  var shouldTerminate: Bool = false
  var authorizationCache = [String: Bool]()

  init?() {
    if let endpointSec = EndpointSecurity() {
      self.endpointSec = endpointSec
    } else {
      return nil
    }

    if let signatureChecker = SignatureChecker() {
      self.signatureChecker = signatureChecker
    } else {
      return nil
    }
  }

  deinit {
  }

  func exec() {
    self.shouldTerminate = false

    while !self.shouldTerminate {
      let messageList = self.endpointSec.getMessages()
      if !messageList.isEmpty {
        self.signatureChecker.addMessagesToQueue(messageList: messageList)
      }

      let processedMessageList = self.signatureChecker.getProcessedMessages()
      for message in processedMessageList {
        if message.signatureStatus != CodeSignatureStatus.Valid {
          self.endpointSec.processMessage(message: message, allow: false)
          print("Automatically denying execution for binary with broken signature: ", message.binaryPath)

        } else {
          var allowExecution: Bool

          if self.authorizationCache[message.binaryPath] != nil {
            allowExecution = self.authorizationCache[message.binaryPath]!
            print("Applying cached decision for ", message.binaryPath)
          } else {
            allowExecution = AuthorizationManager.dialogOKCancel(binaryPath: message.binaryPath)
            self.authorizationCache[message.binaryPath] = allowExecution
          }

          self.endpointSec.processMessage(message: message, allow: allowExecution)
        }
      }
    }
  }

  func terminate() {
    self.shouldTerminate = true
  }

  static func dialogOKCancel(binaryPath: String) -> Bool {
    let messageBox = NSAlert()

    messageBox.messageText = binaryPath
    messageBox.informativeText = "Allow execution?"
    messageBox.alertStyle = .warning
    messageBox.addButton(withTitle: "Allow")
    messageBox.addButton(withTitle: "Deny")

    return messageBox.runModal() == .alertFirstButtonReturn
  }
}
