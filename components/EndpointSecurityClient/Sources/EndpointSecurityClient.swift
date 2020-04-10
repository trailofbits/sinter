/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import EndpointSecurity
import Foundation

import LibSinter

private struct MessageMapEntry {
    public var binaryPath: String
    public var unsafeMessagePtr: UnsafeMutablePointer<es_message_t>
}

private typealias MessageMap = [Int64: MessageMapEntry]

private struct EndpointSecurityClientContext {
    public var authorizationMessageMap = MessageMap()
    public var cachedPathList = Set<String>()

    @Atomic private var identifierGenerator: Int64 = 0
    public var nextIdentifier: Int64 {
        mutating get {
            identifierGenerator += 1
            return identifierGenerator
        }

        set {
            fatalError("nextIdentifier is read-only")
        }
    }
}

private final class EndpointSecurityClient: EndpointSecurityInterface {
    private var context = EndpointSecurityClientContext()
    private let logger: LoggerInterface
    private var esClientOpt: OpaquePointer?

    private init(logger: LoggerInterface,
                 callback: @escaping EndpointSecurityCallback) throws {
        self.logger = logger

        let clientErr = es_new_client(&esClientOpt) { _, unsafeMessagePtr in
            if unsafeMessagePtr.pointee.event_type == ES_EVENT_TYPE_AUTH_EXEC {
                EndpointSecurityClient.processExecAuthorizationEvent(context: &self.context,
                                                                     esClient: self.esClientOpt!,
                                                                     logger: logger,
                                                                     unsafeMessagePtr: unsafeMessagePtr,
                                                                     callback: callback)

            } else if unsafeMessagePtr.pointee.event_type == ES_EVENT_TYPE_NOTIFY_WRITE {
                EndpointSecurityClient.processWriteNotificationEvent(context: &self.context,
                                                                     esClient: self.esClientOpt!,
                                                                     logger: logger,
                                                                     unsafeMessagePtr: unsafeMessagePtr,
                                                                     callback: callback)

            } else {
                logger.logMessage(severity: LoggerMessageSeverity.error,
                                  message: "Invalid event type received in EndpointSecurityClient")
            }
        }

        if clientErr != ES_NEW_CLIENT_RESULT_SUCCESS {
            throw EndpointSecurityError.initializationError
        }

        let cacheErr = es_clear_cache(esClientOpt!)
        if cacheErr != ES_CLEAR_CACHE_RESULT_SUCCESS {
            throw EndpointSecurityError.cacheClearError
        }

        var eventTypeList: [es_event_type_t] = [ES_EVENT_TYPE_AUTH_EXEC,
                                                ES_EVENT_TYPE_NOTIFY_WRITE]

        let subscriptionErr = es_subscribe(esClientOpt!,
                                           &eventTypeList,
                                           UInt32(eventTypeList.count))

        if subscriptionErr != ES_RETURN_SUCCESS {
            throw EndpointSecurityError.subscriptionError
        }
    }

    deinit {
        if let esClient = self.esClientOpt {
            es_unsubscribe_all(esClient)
            es_delete_client(esClient)
        }
    }

    static func create(logger: LoggerInterface,
                       callback: @escaping EndpointSecurityCallback) -> Result<EndpointSecurityInterface, Error> {
        Result<EndpointSecurityInterface, Error> { try EndpointSecurityClient(logger: logger,
                                                                              callback: callback) }
    }

    public func setAuthorization(identifier: Int64, allow: Bool, cache: Bool) -> Bool {
        var succeeded = false

        atomic {
            succeeded = EndpointSecurityClient.setAuthorizationInternal(context: &self.context,
                                                                        esClient: self.esClientOpt!,
                                                                        logger: self.logger,
                                                                        identifier: identifier,
                                                                        allow: allow,
                                                                        cache: cache)
        }

        return succeeded
    }

    public func invalidateCache() -> Bool {
        var succeeded = false

        atomic {
            succeeded = EndpointSecurityClient.invalidateCacheInternal(context: &context,
                                                                       esClient: esClientOpt!,
                                                                       logger: logger)
        }

        return succeeded
    }

    private static func setAuthorizationInternal(context: inout EndpointSecurityClientContext,
                                                 esClient: OpaquePointer,
                                                 logger: LoggerInterface,
                                                 identifier: Int64,
                                                 allow: Bool,
                                                 cache: Bool) -> Bool {
        if let messageMapEntry = context.authorizationMessageMap[identifier] {
            context.authorizationMessageMap.removeValue(forKey: identifier)

            if cache {
                context.cachedPathList.insert(messageMapEntry.binaryPath)
            }

            let authAction = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            es_respond_auth_result(esClient,
                                   messageMapEntry.unsafeMessagePtr,
                                   authAction, cache)

            es_free_message(messageMapEntry.unsafeMessagePtr)

            return true

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "Invalid identifier passed to setAuthorization")

            return false
        }
    }

    private static func invalidateCacheInternal(context: inout EndpointSecurityClientContext,
                                                esClient: OpaquePointer,
                                                logger: LoggerInterface) -> Bool {
        var succeeded = false

        let cacheErr = es_clear_cache(esClient)
        if cacheErr != ES_CLEAR_CACHE_RESULT_SUCCESS {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "Failed to invalidate the EndpointSecurity cache")

        } else {
            context.cachedPathList.removeAll()
            succeeded = true
        }

        return succeeded
    }

    private static func processExecAuthorizationEvent(context: inout EndpointSecurityClientContext,
                                                      esClient: OpaquePointer,
                                                      logger: LoggerInterface,
                                                      unsafeMessagePtr: UnsafePointer<es_message_t>,
                                                      callback: @escaping EndpointSecurityCallback) {
        if unsafeMessagePtr.pointee.event_type != ES_EVENT_TYPE_AUTH_EXEC {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "Not an ES_EVENT_TYPE_AUTH_EXEC event")

            return
        }

        let unsafeMsgPtrCopyOpt = es_copy_message(unsafeMessagePtr)
        if unsafeMsgPtrCopyOpt == nil {
            es_respond_auth_result(esClient,
                                   unsafeMessagePtr,
                                   ES_AUTH_RESULT_DENY,
                                   false)

            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "Failed to duplicate the es_message_t object. Denying execution")

            return
        }

        if var message = EndpointSecurityClient.parseExecAuthorization(esMessage: unsafeMsgPtrCopyOpt!.pointee) {
            message.identifier = context.nextIdentifier

            atomic {
                let messageMapEntry = MessageMapEntry(binaryPath: message.binaryPath,
                                                      unsafeMessagePtr: unsafeMsgPtrCopyOpt!)

                context.authorizationMessageMap[message.identifier] = messageMapEntry
                callback(EndpointSecurityMessage.ExecAuthorization(message))
            }

        } else {
            es_respond_auth_result(esClient,
                                   unsafeMsgPtrCopyOpt!,
                                   ES_AUTH_RESULT_DENY,
                                   false)

            es_free_message(unsafeMsgPtrCopyOpt!)

            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "Failed to parse the es_message_t object. Denying execution")
        }
    }

    private static func processWriteNotificationEvent(context: inout EndpointSecurityClientContext,
                                                      esClient: OpaquePointer,
                                                      logger: LoggerInterface,
                                                      unsafeMessagePtr: UnsafePointer<es_message_t>,
                                                      callback: @escaping EndpointSecurityCallback) {
        if unsafeMessagePtr.pointee.event_type != ES_EVENT_TYPE_NOTIFY_WRITE {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "Not an ES_EVENT_TYPE_NOTIFY_WRITE event")

            return
        }

        if let message = EndpointSecurityClient.parseWriteNotification(esMessage: unsafeMessagePtr.pointee) {
            atomic {
                for cachedPath in context.cachedPathList {
                    if message.filePath.starts(with: cachedPath) {
                        _ = EndpointSecurityClient.invalidateCacheInternal(context: &context,
                                                                           esClient: esClient,
                                                                           logger: logger)
                    }
                }

                for authorizationMessage in context.authorizationMessageMap {
                    if message.filePath.starts(with: authorizationMessage.value.binaryPath) {
                        context.authorizationMessageMap.removeValue(forKey: authorizationMessage.key)

                        let notification = EndpointSecurityExecInvalidationNotification(identifier: authorizationMessage.key,
                                                                                        binaryPath: authorizationMessage.value.binaryPath)

                        _ = EndpointSecurityClient.setAuthorizationInternal(context: &context,
                                                                            esClient: esClient,
                                                                            logger: logger,
                                                                            identifier: authorizationMessage.key,
                                                                            allow: false,
                                                                            cache: false)

                        callback(EndpointSecurityMessage.ExecInvalidationNotification(notification))
                    }
                }

                callback(EndpointSecurityMessage.WriteNotification(message))
            }

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "Failed to parse the es_message_t object. Ignoring write notification and clearing the EndpointSecurity cache")

            _ = EndpointSecurityClient.invalidateCacheInternal(context: &context,
                                                               esClient: esClient,
                                                               logger: logger)

            callback(EndpointSecurityMessage.InvalidWriteNotification)
        }
    }

    private static func parseExecAuthorization(esMessage: es_message_t) -> EndpointSecurityExecAuthorization? {
        if esMessage.event_type != ES_EVENT_TYPE_AUTH_EXEC {
            return nil
        }

        let target = esMessage.event.exec.target.pointee
        let binaryPath = EndpointSecurityClient.getProcessBinaryPath(process: target)

        let parentProcessId = target.ppid
        let processId = audit_token_to_pid(target.audit_token)

        let userId = audit_token_to_euid(target.audit_token)
        let groupId = target.group_id

        let signingIdentifier = EndpointSecurityClient.getProcessSigningId(process: target)
        let teamIdentifier = EndpointSecurityClient.getProcessTeamId(process: target)
        let platformBinary = target.is_platform_binary

        let cdHash = EndpointSecurityClient.getProcessCdHash(process: target)
        let codeDirectoryHash = BinaryHash(type: BinaryHashType.truncatedSha256,
                                           hash: cdHash)

        let parsedMessage = EndpointSecurityExecAuthorization(binaryPath: binaryPath,
                                                              parentProcessId: pid_t(parentProcessId),
                                                              processId: pid_t(processId),
                                                              userId: uid_t(userId),
                                                              groupId: gid_t(groupId),
                                                              codeDirectoryHash: codeDirectoryHash,
                                                              signingIdentifier: signingIdentifier,
                                                              teamIdentifier: teamIdentifier,
                                                              platformBinary: platformBinary)

        return parsedMessage
    }

    private static func parseWriteNotification(esMessage: es_message_t) -> EndpointSecurityWriteNotification? {
        let filePath = getFilePath(file: esMessage.event.write.target.pointee)
        let parsedMessage = EndpointSecurityWriteNotification(filePath: filePath)
        return parsedMessage
    }

    private static func getFilePath(file: es_file_t) -> String {
        // TODO: use path.size
        String(cString: file.path.data)
    }

    private static func getProcessBinaryPath(process: es_process_t) -> String {
        let binaryPath = getFilePath(file: process.executable.pointee)

        var bundleURL = URL(fileURLWithPath: binaryPath)
        for _ in 1 ... 3 {
            bundleURL.deleteLastPathComponent()
        }

        let bundleCodeSignatureURL = bundleURL.appendingPathComponent("Contents/_CodeSignature")

        let validURLOpt = try? bundleCodeSignatureURL.checkResourceIsReachable()
        if validURLOpt != nil {
            return bundleURL.path
        }

        return binaryPath
    }

    private static func getProcessCdHash(process: es_process_t) -> String {
        // Convert the tuple of UInt8 bytes to its hexadecimal string form
        let CDhashArray = CDhash(tuple: process.cdhash).array
        var cdhashHexString: String = ""
        for eachByte in CDhashArray {
            cdhashHexString += String(format: "%02X", eachByte)
        }

        return cdhashHexString
    }

    private static func getProcessTeamId(process: es_process_t) -> String {
        var teamIdString: String = ""
        if process.team_id.length > 0 {
            teamIdString = String(cString: process.team_id.data)
        }

        return teamIdString
    }

    private static func getProcessSigningId(process: es_process_t) -> String {
        var signingIdString: String = ""
        if process.signing_id.length > 0 {
            signingIdString = String(cString: process.signing_id.data)
        }

        return signingIdString
    }
}

public func createEndpointSecurityClient(logger: LoggerInterface,
                                         callback: @escaping EndpointSecurityCallback) -> Result<EndpointSecurityInterface, Error> {
    EndpointSecurityClient.create(logger: logger,
                                  callback: callback)
}

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
