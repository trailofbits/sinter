/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

import EndpointSecurity
import Dispatch

class EndpointSecurity {
  var es_client: OpaquePointer?

  let message_list_queue = DispatchQueue(label: "EndpointSecurity_message_list")
  var message_list = [EndpointSecurityMessage]()
  let message_list_sem = DispatchSemaphore(value: 0)

  init?() {
    let client_err = es_new_client(&self.es_client) {
      (es_client, unsafe_message_ptr) in
        let message = EndpointSecurity.generateEndpointSecurityMessage(unsafe_msg_ptr: unsafe_message_ptr);

        self.message_list_queue.sync {
          self.message_list.append(message);
          self.message_list_sem.signal()
        }
    }

    if (client_err != ES_NEW_CLIENT_RESULT_SUCCESS) {
      return nil;
    }

    let cache_err = es_clear_cache(self.es_client!);
    if (cache_err != ES_CLEAR_CACHE_RESULT_SUCCESS) {
      return nil;
    }

    var event_type: es_event_type_t = ES_EVENT_TYPE_AUTH_EXEC;
    let subscription_err = es_subscribe(self.es_client!, &event_type, 1);
    if (subscription_err != ES_RETURN_SUCCESS) {
      return nil;
    }
  }

  deinit {
    es_unsubscribe_all(self.es_client!);
    es_delete_client(self.es_client!);
  }

  func getMessages() -> [EndpointSecurityMessage] {
    var message_list = [EndpointSecurityMessage]();

    if (self.message_list_sem.wait(timeout: .now() + 5) != .success) {
      return [EndpointSecurityMessage]()
    }

    self.message_list_queue.sync {
      message_list = self.message_list;
      self.message_list = [EndpointSecurityMessage]()
    }

    return message_list;
  }

  func processMessage(message: EndpointSecurityMessage, allow: Bool) {
    let auth_action = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
    es_respond_auth_result(self.es_client!, message.unsafe_msg_ptr, auth_action, false)
    es_free_message(message.unsafe_msg_ptr)

    print("> allowed:", allow, ": ", message.binary_path)
  }

  static func processBinaryPath(process: es_process_t) -> String? {
    let executable = process.executable!.pointee;
    let path = String(cString: executable.path.data); // todo: use path.size

    return path;
  }

  static func generateEndpointSecurityMessage(unsafe_msg_ptr: UnsafePointer<es_message_t>) -> EndpointSecurityMessage {
    let unsafe_msg_ptr_copy = es_copy_message(unsafe_msg_ptr);

    let message = unsafe_msg_ptr_copy!.pointee;

    let binary_path = EndpointSecurity.processBinaryPath(process: message.event.exec.target!.pointee);

    return EndpointSecurityMessage(
      unsafe_msg_ptr: unsafe_msg_ptr_copy!,
      binary_path: binary_path!
    )
  }
}

