/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import EndpointSecurity
import Logger
import Configuration

private let eventExpirationTime: Double = 10

struct MessageMapEntry {
    public var key: Int64
    public var timestamp: Double
    public var binaryPath: String
    public var unsafeMessagePtr: UnsafeMutablePointer<es_message_t>
}

typealias MessageMap = [Int64: MessageMapEntry]

struct EndpointSecurityClientContext {
    public var allowUnsignedPrograms = false
    public var authorizationMessageMap = MessageMap()
    public var cachedPathList = Set<String>()
}

final class EndpointSecurityClient: EndpointSecurityInterface, ConfigurationSubscriberInterface {
    private var context = EndpointSecurityClientContext()

    private let api: EndpointSecurityAPIInterface
    private let logger: LoggerInterface
    private var esClientOpt: OpaquePointer?
    private var eventExpirationTimer = Timer()

    private init(api: EndpointSecurityAPIInterface,
                 configuration: ConfigurationInterface,
                 logger: LoggerInterface,
                 callback: @escaping EndpointSecurityCallback) throws {

        self.api = api
        self.logger = logger
        
        configuration.subscribe(subscriber: self)

        let clientErr = api.newClient(client: &esClientOpt) { _, unsafeMessagePtr in
            self.endpointSecurityCallback(unsafeMessagePtr: unsafeMessagePtr,
                                          callback: callback)

        }

        if clientErr != ES_NEW_CLIENT_RESULT_SUCCESS {
            throw EndpointSecurityError.initializationError
        }

        let cacheErr = es_clear_cache(esClientOpt!)
        if cacheErr != ES_CLEAR_CACHE_RESULT_SUCCESS {
            throw EndpointSecurityError.cacheClearError
        }

        var eventTypeList: [es_event_type_t] = [ES_EVENT_TYPE_AUTH_EXEC,
                                                ES_EVENT_TYPE_NOTIFY_WRITE,
                                                ES_EVENT_TYPE_NOTIFY_UNLINK,
                                                ES_EVENT_TYPE_NOTIFY_RENAME,
                                                ES_EVENT_TYPE_NOTIFY_MMAP,
                                                ES_EVENT_TYPE_NOTIFY_LINK,
                                                ES_EVENT_TYPE_NOTIFY_TRUNCATE,
                                                ES_EVENT_TYPE_NOTIFY_CREATE]

        let subscriptionErr = api.subscribe(client: esClientOpt!,
                                            events: &eventTypeList,
                                            eventCount: UInt32(eventTypeList.count))

        if subscriptionErr != ES_RETURN_SUCCESS {
            throw EndpointSecurityError.subscriptionError
        }

        eventExpirationTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(eventExpirationTime),
                                                    repeats: true) { _ in

            EndpointSecurityClient.onEventExpiration(context: &self.context,
                                                     api: self.api,
                                                     logger: self.logger,
                                                     client: self.esClientOpt!,
                                                     callback: callback)
        }
    }

    deinit {
        if let esClient = esClientOpt {
            _ = api.unsubscribeAll(client: esClient)
            _ = api.deleteClient(client: esClient)
        }

        eventExpirationTimer.invalidate()
    }

    static func create(api: EndpointSecurityAPIInterface,
                       configuration: ConfigurationInterface,
                       logger: LoggerInterface,
                       callback: @escaping EndpointSecurityCallback) -> Result<EndpointSecurityInterface, Error> {

        Result<EndpointSecurityInterface, Error> { try EndpointSecurityClient(api: api,
                                                                              configuration: configuration,
                                                                              logger: logger,
                                                                              callback: callback) }
    }

    func onConfigurationChange(configuration: ConfigurationInterface) {
        EndpointSecurityClient.readConfiguration(context: &context,
                                                 configuration: configuration,
                                                 logger: logger)
    }

    public func setAuthorization(identifier: Int64, allow: Bool, cache: Bool) -> Bool {
        var succeeded = false

        atomic {
            succeeded = EndpointSecurityClient.setAuthorization(context: &context,
                                                                api: api,
                                                                logger: logger,
                                                                client: esClientOpt!,
                                                                identifier: identifier,
                                                                allow: allow,
                                                                cache: cache)
        }

        return succeeded
    }

    public func invalidateCache() -> Bool {
        var succeeded = false

        atomic {
            succeeded = EndpointSecurityClient.invalidateCache(context: &context,
                                                               api: api,
                                                               client: esClientOpt!,
                                                               logger: logger)
        }

        return succeeded
    }

    private func onExecEvent(unsafeMessagePtr: UnsafePointer<es_message_t>,
                             callback: @escaping EndpointSecurityCallback) {

        // Reject unsigned programs if they are not allowed
        let target = unsafeMessagePtr.pointee.event.exec.target.pointee
        let signingIdentifier = getProcessSigningId(process: target)

        if signingIdentifier.isEmpty && !context.allowUnsignedPrograms {
            _ = api.respondAuthResult(client: esClientOpt!,
                                      message: unsafeMessagePtr,
                                      result: ES_AUTH_RESULT_DENY,
                                      cache: true)
            
            return
        }

        // Copy the message and save it, so we can respond to it later
        let unsafeMsgPtrCopyOpt = es_copy_message(unsafeMessagePtr)
        if unsafeMsgPtrCopyOpt == nil {
            _ = api.respondAuthResult(client: esClientOpt!,
                                      message: unsafeMessagePtr,
                                      result: ES_AUTH_RESULT_DENY,
                                      cache: false)

            logger.logMessage(severity: .error,
                              message: "Failed to duplicate the es_message_t object. Denying execution")

            return
        }

        if var message = parseExecAuthorization(esMessage: unsafeMsgPtrCopyOpt!.pointee) {
            message.identifier = identifierGenerator.generate()

            atomic {
                let timestamp = NSDate().timeIntervalSince1970
                let messageMapEntry = MessageMapEntry(key: message.identifier,
                                                      timestamp: timestamp,
                                                      binaryPath: message.binaryPath,
                                                      unsafeMessagePtr: unsafeMsgPtrCopyOpt!)

                context.authorizationMessageMap[message.identifier] = messageMapEntry
                callback(EndpointSecurityMessage.ExecAuthorization(message))
            }

        } else {
            _ = api.respondAuthResult(client: esClientOpt!,
                                     message: unsafeMsgPtrCopyOpt!,
                                     result: ES_AUTH_RESULT_DENY,
                                     cache: false)

            _ = api.freeMessage(msg: unsafeMsgPtrCopyOpt!)

            logger.logMessage(severity: .error,
                              message: "Failed to parse the es_message_t object. Denying execution")
        }
    }

    private func onFileChangeEvent(unsafeMessagePtr: UnsafePointer<es_message_t>,
                                   callback: @escaping EndpointSecurityCallback) {

        let eventType = unsafeMessagePtr.pointee.event_type
        var messageOpt: EndpointSecurityFileChangeNotification?

        switch eventType {
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            messageOpt = parseWriteNotification(esMessage: unsafeMessagePtr.pointee)

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            messageOpt = parseUnlinkNotification(esMessage: unsafeMessagePtr.pointee)

        case ES_EVENT_TYPE_NOTIFY_RENAME:
            messageOpt = parseRenameNotification(esMessage: unsafeMessagePtr.pointee)

        case ES_EVENT_TYPE_NOTIFY_MMAP:
            // Ignore read-only mmap() requests
            messageOpt = parseMmapNotification(esMessage: unsafeMessagePtr.pointee)
            if messageOpt == nil {
                return
            }

        case ES_EVENT_TYPE_NOTIFY_LINK:
            messageOpt = parseLinkNotification(esMessage: unsafeMessagePtr.pointee)

        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            messageOpt = parseTruncateNotification(esMessage: unsafeMessagePtr.pointee)

        case ES_EVENT_TYPE_NOTIFY_CREATE:
            messageOpt = parseCreateNotification(esMessage: unsafeMessagePtr.pointee)

        case _:
            logger.logMessage(severity: .error, message: "Invalid/unsupported event received in onFileChangeEvent")
            return
        }

        if messageOpt == nil {
            logger.logMessage(severity: .error, message: "Failed to parse a file change event")
            return
        }

        atomic {
            var resetCache = false
            var invalidatedRequestList = [MessageMapEntry]()
            
            EndpointSecurityClient.processFileChangeNotification(context: &context,
                                                                 resetCache: &resetCache,
                                                                 invalidatedRequestList: &invalidatedRequestList,
                                                                 message: messageOpt!)

            if resetCache {
                _ = EndpointSecurityClient.invalidateCache(context: &context,
                                                           api: api,
                                                           client: esClientOpt!,
                                                           logger: logger)
            }
            
            for invalidatedRequest in invalidatedRequestList {
                let notification = EndpointSecurityExecInvalidationNotification(identifier: invalidatedRequest.key,
                                                                                binaryPath: invalidatedRequest.binaryPath,
                                                                                reason: .applicationChanged)

                callback(EndpointSecurityMessage.ExecInvalidationNotification(notification))
            }
            
            callback(EndpointSecurityMessage.ChangeNotification(messageOpt!))
        }
    }

    private func endpointSecurityCallback(unsafeMessagePtr: UnsafePointer<es_message_t>,
                                          callback: @escaping EndpointSecurityCallback) {

        let eventType = unsafeMessagePtr.pointee.event_type

        switch eventType {
        case ES_EVENT_TYPE_AUTH_EXEC:
            onExecEvent(unsafeMessagePtr: unsafeMessagePtr,
                        callback: callback)

        case ES_EVENT_TYPE_NOTIFY_WRITE,
             ES_EVENT_TYPE_NOTIFY_UNLINK,
             ES_EVENT_TYPE_NOTIFY_RENAME,
             ES_EVENT_TYPE_NOTIFY_MMAP,
             ES_EVENT_TYPE_NOTIFY_LINK,
             ES_EVENT_TYPE_NOTIFY_TRUNCATE,
             ES_EVENT_TYPE_NOTIFY_CREATE:

            onFileChangeEvent(unsafeMessagePtr: unsafeMessagePtr,
                              callback: callback)

        case _:
            logger.logMessage(severity: .error,
                              message: "Invalid/unsupported event received in the EndpointSecurityClient read callback")
        }
    }

    static func readConfiguration(context: inout EndpointSecurityClientContext,
                                  configuration: ConfigurationInterface,
                                  logger: LoggerInterface) -> Void {

        var newAllowUnsignedPrograms = false

        if let allowUnsignedPrograms = configuration.booleanValue(section: "Sinter",
                                                                   key: "allow_unsigned_programs") {
            newAllowUnsignedPrograms = allowUnsignedPrograms

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'allow_unsigned_programs' key is missing from the Sinter section")
        }

        context.allowUnsignedPrograms = newAllowUnsignedPrograms
    }

    static func onEventExpiration(context: inout EndpointSecurityClientContext,
                                  api: EndpointSecurityAPIInterface,
                                  logger: LoggerInterface,
                                  client: OpaquePointer,
                                  callback: @escaping EndpointSecurityCallback) {

        let currentTimestamp = NSDate().timeIntervalSince1970
        var expiredMessageList = [MessageMapEntry]()

        atomic {
            EndpointSecurityClient.expireEvents(context: &context,
                                                expiredMessageList: &expiredMessageList,
                                                currentTimestamp: currentTimestamp,
                                                maxRequestAge: eventExpirationTime)


            for expiredMessage in expiredMessageList {
                let notification = EndpointSecurityExecInvalidationNotification(identifier: expiredMessage.key,
                                                                                binaryPath: expiredMessage.binaryPath,
                                                                                reason: .expired)

                callback(EndpointSecurityMessage.ExecInvalidationNotification(notification))
                
                _ = EndpointSecurityClient.setAuthorization(context: &context,
                                                            api: api,
                                                            logger: logger,
                                                            client: client,
                                                            identifier: expiredMessage.key,
                                                            allow: false,
                                                            cache: false)
            }
        }
    }

    static func expireEvents(context: inout EndpointSecurityClientContext,
                             expiredMessageList: inout [MessageMapEntry],
                             currentTimestamp: TimeInterval,
                             maxRequestAge: TimeInterval) {
        
        expiredMessageList = [MessageMapEntry]()

        var keyList = [Int64]()
        for messageIterator in context.authorizationMessageMap {
            let elapsedTime = currentTimestamp - messageIterator.value.timestamp
            if elapsedTime < maxRequestAge {
                continue
            }
            
            expiredMessageList.append(messageIterator.value)
            keyList.append(messageIterator.key)
        }
        
        for key in keyList {
            context.authorizationMessageMap.removeValue(forKey: key)
        }
    }

    static func setAuthorization(context: inout EndpointSecurityClientContext,
                                 api: EndpointSecurityAPIInterface,
                                 logger: LoggerInterface,
                                 client: OpaquePointer,
                                 identifier: Int64,
                                 allow: Bool,
                                 cache: Bool) -> Bool {

        if let messageMapEntry = context.authorizationMessageMap[identifier] {
            context.authorizationMessageMap.removeValue(forKey: identifier)

            if cache {
                context.cachedPathList.insert(messageMapEntry.binaryPath)
            }

            let authAction = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
            _ = api.respondAuthResult(client: client,
                                      message: messageMapEntry.unsafeMessagePtr,
                                      result: authAction,
                                      cache: cache)

            api.freeMessage(msg: messageMapEntry.unsafeMessagePtr)
            return true

        } else {
            logger.logMessage(severity: .error,
                              message: "Invalid identifier passed to setAuthorization")

            return false
        }
    }

    static func invalidateCache(context: inout EndpointSecurityClientContext,
                                api: EndpointSecurityAPIInterface,
                                client: OpaquePointer,
                                logger: LoggerInterface) -> Bool {

        if api.clearCache(client: client) == ES_CLEAR_CACHE_RESULT_SUCCESS {
            context.cachedPathList.removeAll()
            return true

        } else {
            logger.logMessage(severity: .error,
                              message: "Failed to clear the EndpointSecurity cache")
            
            return false
        }
    }

    static func processFileChangeNotification(context: inout EndpointSecurityClientContext,
                                              resetCache: inout Bool,
                                              invalidatedRequestList: inout [MessageMapEntry],
                                              message: EndpointSecurityFileChangeNotification) {

        resetCache = false
        invalidatedRequestList = [MessageMapEntry]()

        for filePath in message.pathList {
            if !resetCache && context.cachedPathList.contains(filePath) {
                resetCache = true
            }
            
            var keyList = [Int64]()
            for authorizationMessage in context.authorizationMessageMap {
                if !filePath.starts(with: authorizationMessage.value.binaryPath) {
                    continue
                }

                keyList.append(authorizationMessage.key)
                invalidatedRequestList.append(authorizationMessage.value)
            }
            
            for key in keyList {
                context.authorizationMessageMap.removeValue(forKey: key)
            }
        }
    }
}

public func createEndpointSecurityClient(configuration: ConfigurationInterface,
                                         logger: LoggerInterface,
                                         callback: @escaping EndpointSecurityCallback) -> Result<EndpointSecurityInterface, Error> {

    EndpointSecurityClient.create(api: createSystemEndpointSecurityAPI(),
                                  configuration: configuration,
                                  logger: logger,
                                  callback: callback)
}
