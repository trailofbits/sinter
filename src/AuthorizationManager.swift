import Foundation
import Cocoa

class AuthorizationManager {
  var endpoint_security: EndpointSecurity
  var signature_checker: SignatureChecker

  var should_terminate: Bool = false
  var authorization_cache = [String: Bool]()

  init?() {
    if let endpoint_security = EndpointSecurity() {
      self.endpoint_security = endpoint_security;
    } else {
      return nil
    }

    if let signature_checker = SignatureChecker() {
      self.signature_checker = signature_checker;
    } else {
      return nil
    }
  }

  deinit {
  }

  func exec() {
    self.should_terminate = false;

    while (!self.should_terminate) {
      let message_list = self.endpoint_security.getMessages()
      if (!message_list.isEmpty) {
        self.signature_checker.addMessagesToQueue(message_list: message_list)
      }

      let processed_message_list = self.signature_checker.getProcessedMessages();
      for message in processed_message_list {
        if (message.signature_status != CodeSignatureStatus.Valid) {
          self.endpoint_security.processMessage(message: message, allow: false)
          print("Automatically denying execution for binary with broken signature: ", message.binary_path)

        } else {
          var allow_execution: Bool;

          if (self.authorization_cache[message.binary_path] != nil) {
            allow_execution = self.authorization_cache[message.binary_path]!
            print("Applying cached decision for ", message.binary_path)
          } else {
            allow_execution = AuthorizationManager.dialogOKCancel(binary_path: message.binary_path)
            self.authorization_cache[message.binary_path] = allow_execution
          }

          self.endpoint_security.processMessage(message: message, allow:allow_execution)
        }
      }
    }
  }

  func terminate() {
    self.should_terminate = true;
  }


  static func dialogOKCancel(binary_path: String) -> Bool {
    let message_box = NSAlert()

    message_box.messageText = binary_path
    message_box.informativeText = "Allow execution?"
    message_box.alertStyle = .warning
    message_box.addButton(withTitle: "Allow")
    message_box.addButton(withTitle: "Deny")

    return message_box.runModal() == .alertFirstButtonReturn
  }
}
