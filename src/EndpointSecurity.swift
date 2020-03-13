/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

import EndpointSecurity
import Dispatch

class EndpointSecurity {
  var esClient: OpaquePointer?

  let messageListQueeu = DispatchQueue(label: "EndpointSecurity_message_list")
  var messageList = [EndpointSecurityMessage]()
  let messageListSem = DispatchSemaphore(value: 0)

  init?() {
    let clientErr = es_new_client(&self.esClient) { (_, unsafeMessagePtr) in
        let message = EndpointSecurity.generateEndpointSecurityMessage(unsafeMsgPtr: unsafeMessagePtr)

        self.messageListQueeu.sync {
          self.messageList.append(message)
          self.messageListSem.signal()
        }
    }

    if clientErr != ES_NEW_CLIENT_RESULT_SUCCESS {
      return nil
    }

    let cacheErr = es_clear_cache(self.esClient!)
    if cacheErr != ES_CLEAR_CACHE_RESULT_SUCCESS {
      return nil
    }

    var eventType: es_event_type_t = ES_EVENT_TYPE_AUTH_EXEC
    let subscriptionErr = es_subscribe(self.esClient!, &eventType, 1)
    if subscriptionErr != ES_RETURN_SUCCESS {
      return nil
    }
  }

  deinit {
    es_unsubscribe_all(self.esClient!)
    es_delete_client(self.esClient!)
  }

  func getMessages() -> [EndpointSecurityMessage] {
    var messageList = [EndpointSecurityMessage]()

    if self.messageListSem.wait(timeout: .now() + 5) != .success {
      return [EndpointSecurityMessage]()
    }

    self.messageListQueeu.sync {
      messageList = self.messageList
      self.messageList = [EndpointSecurityMessage]()
    }

    return messageList
  }

  func processMessage(message: EndpointSecurityMessage, allow: Bool) {
    let authAction = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
    es_respond_auth_result(self.esClient!, message.unsafeMsgPtr, authAction, false)
    es_free_message(message.unsafeMsgPtr)

    print("> allowed:", allow, ": ", message.binaryPath)
  }

  static func processBinaryPath(process: es_process_t) -> String? {
    let executable = process.executable!.pointee
    let path = String(cString: executable.path.data) // todo: use path.size

    return path
  }

  static func generateEndpointSecurityMessage(unsafeMsgPtr: UnsafePointer<es_message_t>) -> EndpointSecurityMessage {
    let unsafeMsgPtrCopy = es_copy_message(unsafeMsgPtr)

    let message = unsafeMsgPtrCopy!.pointee

    let binaryPath = EndpointSecurity.processBinaryPath(process: message.event.exec.target!.pointee)

    return EndpointSecurityMessage(
      unsafeMsgPtr: unsafeMsgPtrCopy!,
      binaryPath: binaryPath!
    )
  }
}
