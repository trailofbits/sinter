/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import AuthorizationManager
import EndpointSecurityWrapper
import Logger

import Darwin.bsm
import Foundation

// Because a Swift tuple cannot/shouldn't be iterated at runtime,
// use an UnsafeBufferPointer to store the twenty UInt8 values of
// the cdhash (a tuple of UInt8 values) into an iterable array form
private struct CDhash {
    public var tuple: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                       UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
                       UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)

    public var array: [UInt8] {
        var tmp = tuple
        return [UInt8](UnsafeBufferPointer(start: &tmp.0, count: MemoryLayout.size(ofValue: tmp)))
    }
}

class EndpointSecurityClient: IEndpointSecurityClient {
    private let logger: ILogger
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

    public init?(logger: ILogger) {
        self.logger = logger

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

            let binaryPath = EndpointSecurityClient.getProcessBinaryPath(process: target.pointee)

            let ppid = target.pointee.ppid
            let pid = audit_token_to_pid(target.pointee.audit_token)

            let uid = audit_token_to_euid(target.pointee.audit_token)
            let gid = target.pointee.group_id

            let cdhash = EndpointSecurityClient.getProcessCdHash(process: target.pointee)
            let signingId = EndpointSecurityClient.getProcessSigningId(process: target.pointee)
            let teamId = EndpointSecurityClient.getProcessTeamId(process: target.pointee)
            let isAppleSigned = target.pointee.is_platform_binary

            let message = IEndpointSecurityClientMessage(messageId: identifier,
                                                         binaryPath: binaryPath,
                                                         parentProcessId: ppid,
                                                         processId: pid,
                                                         userId: uid,
                                                         groupId: gid_t(gid),
                                                         cdhash: cdhash,
                                                         signingId: signingId,
                                                         teamId: teamId,
                                                         isAppleSigned: isAppleSigned)

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

    static func getProcessBinaryPath(process: es_process_t) -> String {
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

    static func getProcessCdHash(process: es_process_t) -> String {
        // Convert the tuple of UInt8 bytes to its hexadecimal string form
        let CDhashArray = CDhash(tuple: process.cdhash).array
        var cdhashHexString: String = ""
        for eachByte in CDhashArray {
            cdhashHexString += String(format: "%02X", eachByte)
        }

        return cdhashHexString
    }

    static func getProcessTeamId(process: es_process_t) -> String {
        var teamIdString: String = ""
        if process.team_id.length > 0 {
            teamIdString = String(cString: process.team_id.data)
        }

        return teamIdString
    }

    static func getProcessSigningId(process: es_process_t) -> String {
        var signingIdString: String = ""
        if process.signing_id.length > 0 {
            signingIdString = String(cString: process.signing_id.data)
        }

        return signingIdString
    }
}
