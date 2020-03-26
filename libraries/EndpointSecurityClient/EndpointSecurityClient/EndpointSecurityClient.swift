/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import CodeSigningUtils
import EndpointSecurity
import Foundation

public struct EndpointSecurityClientMessage {
    public var unsafeMsgPtr: UnsafeMutablePointer<es_message_t>
    public var binaryPath: String
    public var signatureStatus: CodeSignatureStatus?
}

public class EndpointSecurityClient {
    var esClient: OpaquePointer?

    let messageListQueue = DispatchQueue(label: "EndpointSecurity_message_list")
    var messageList = [EndpointSecurityClientMessage]()
    let messageListSem = DispatchSemaphore(value: 0)

    public init?() {
        let clientErr = es_new_client(&esClient) { _, unsafeMessagePtr in
            let message = EndpointSecurityClient.generateEndpointSecurityClientMessage(unsafeMsgPtr: unsafeMessagePtr)

            self.messageListQueue.sync {
                self.messageList.append(message)
                self.messageListSem.signal()
            }
        }

        if clientErr != ES_NEW_CLIENT_RESULT_SUCCESS {
            return nil
        }

        let cacheErr = es_clear_cache(esClient!)
        if cacheErr != ES_CLEAR_CACHE_RESULT_SUCCESS {
            return nil
        }

        var eventType: es_event_type_t = ES_EVENT_TYPE_AUTH_EXEC
        let subscriptionErr = es_subscribe(esClient!, &eventType, 1)
        if subscriptionErr != ES_RETURN_SUCCESS {
            return nil
        }
    }

    deinit {
        if let esClient = self.esClient {
            es_unsubscribe_all(esClient)
            es_delete_client(esClient)
        }
    }

    public func getMessages() -> [EndpointSecurityClientMessage] {
        var messageList = [EndpointSecurityClientMessage]()

        if messageListSem.wait(timeout: .now() + 5) != .success {
            return [EndpointSecurityClientMessage]()
        }

        messageListQueue.sync {
            messageList = self.messageList
            self.messageList = [EndpointSecurityClientMessage]()
        }

        return messageList
    }

    public func processMessage(message: EndpointSecurityClientMessage, allow: Bool) {
        let authAction = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
        es_respond_auth_result(esClient!, message.unsafeMsgPtr, authAction, false)
        es_free_message(message.unsafeMsgPtr)
    }

    static func processBinaryPath(process: es_process_t) -> String? {
        let executable = process.executable.pointee
        let path = String(cString: executable.path.data) // TODO: use path.size

        return path
    }

    static func generateEndpointSecurityClientMessage(unsafeMsgPtr: UnsafePointer<es_message_t>) -> EndpointSecurityClientMessage {
        let unsafeMsgPtrCopy = es_copy_message(unsafeMsgPtr)
        let message = unsafeMsgPtrCopy!.pointee
        let binaryPath = EndpointSecurityClient.processBinaryPath(process: message.event.exec.target.pointee)

        return EndpointSecurityClientMessage(
            unsafeMsgPtr: unsafeMsgPtrCopy!,
            binaryPath: binaryPath!
        )
    }
}
