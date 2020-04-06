/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import AuthorizationManager
import EndpointSecurityWrapper

import Foundation

class EndpointSecurityClient: IEndpointSecurityClient {
    private var esClient: OpaquePointer?

    private var internalMessageMap = [Int64: UnsafeMutablePointer<es_message_t>]()

    private var messageList = [IEndpointSecurityClientMessage]()
    private let messageListSem = DispatchSemaphore(value: 0)

    @Atomic private var identifierGenerator: Int64 = 0
    private var nextIdentifier: Int64 {
        get {
            identifierGenerator += 1
            return identifierGenerator
        }
        set {
            fatalError("nextIdentifier is read-only")
        }
    }

    private var callbackOpt: ((_ message: IEndpointSecurityClientMessage) -> Void)?

    public init?() {
        let clientErr = es_new_client(&esClient) { _, unsafeMessagePtr in
            let unsafeMsgPtrCopy = es_copy_message(unsafeMessagePtr)
            let identifier = self.nextIdentifier

            atomic {
                self.internalMessageMap[identifier] = unsafeMsgPtrCopy
            }

            let endpointSecMessage = unsafeMsgPtrCopy!.pointee

            let target: UnsafeMutablePointer<es_process_t>
            #if canImport(EndpointSecurity)
                target = endpointSecMessage.event.exec.target
            #else
                target = endpointSecMessage.event.exec.target!
            #endif

            let binaryPath = EndpointSecurityClient.processBinaryPath(process: target.pointee)
            let message = IEndpointSecurityClientMessage(messageId: identifier, binaryPath: binaryPath)

            atomic {
                if let callback = self.callbackOpt {
                    for queueMessage in self.messageList {
                        callback(queueMessage)
                    }

                    self.messageList.removeAll()
                    callback(message)

                } else {
                    self.messageList.append(message)
                }
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

    public func setCallback(callback: @escaping (_ message: IEndpointSecurityClientMessage) -> Void) {
        callbackOpt = callback
    }

    public func setAuthorization(messageId: Int64, allow: Bool, cache _: Bool) {
        var internalMessageOpt: UnsafeMutablePointer<es_message_t>?

        atomic {
            internalMessageOpt = self.internalMessageMap[messageId]
            if internalMessageOpt != nil {
                self.internalMessageMap.removeValue(forKey: messageId)
            }
        }

        if internalMessageOpt == nil {
            return
        }

        let authAction = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
        es_respond_auth_result(esClient!, internalMessageOpt!, authAction, false)
        es_free_message(internalMessageOpt!)
    }

    public func invalidateCachedAuthorization(binaryPath _: String) {
        // TODO: find a way to only invalidate binaryPath
        es_clear_cache(esClient!)
    }

    static func processBinaryPath(process: es_process_t) -> String {
        let executable: es_file_t

        #if canImport(EndpointSecurity)
            executable = process.executable.pointee
        #else
            executable = process.executable!.pointee
        #endif

        // TODO: use path.size
        let path = String(cString: executable.path.data)

        return path
    }
}
