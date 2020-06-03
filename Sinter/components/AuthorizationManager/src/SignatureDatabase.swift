/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation
import EndpointSecurityClient
import DecisionManager
import Logger

fileprivate let fileSizeLimit: Int = (1024 * 1024) * 10

public typealias SignatureDatabaseCallback = (EndpointSecurityExecAuthorization,
                                              SignatureDatabaseResult) -> Void

final class SignatureDatabaseContext {
    var operationMap = [String: SignatureDatabaseOperation]()
    var childOperationMap = [String: [SignatureDatabaseOperation]]()
    var resultCache = [String: SignatureDatabaseResult]()

    var primaryOperationQueue = OperationQueue()
    var secondaryOperationQueue = OperationQueue()
}

fileprivate let dispatchQueue = DispatchQueue(label: "com.trailofbits.sinter.signature-database")

final class SignatureDatabase {
    private var context = SignatureDatabaseContext()
    private var logger: LoggerInterface

    public init(logger: LoggerInterface) {
        self.logger = logger
        
        context.primaryOperationQueue = createOperationQueue(type: OperationQueueType.primary)
        context.secondaryOperationQueue = createOperationQueue(type: OperationQueueType.secondary)
    }

    public func checkSignatureFor(message: EndpointSecurityExecAuthorization,
                                  block: @escaping SignatureDatabaseCallback) {

        dispatchQueue.sync {
            if message.codeDirectoryHash.hash.isEmpty {
                context.resultCache[message.binaryPath] = SignatureDatabaseResult.NotSigned
            }

            let cachedResultOpt = context.resultCache[message.binaryPath]

            // If the permissions are correct, Sinter.app will end up in the
            // primary queue
            let queueType = SignatureDatabase.getQueueTypeFor(path: message.binaryPath)
            if message.binaryPath == "/Applications/Sinter.app" &&
                queueType != OperationQueueType.primary {

                logger.logMessage(severity: LoggerMessageSeverity.error,
                                  message: "Wrong permissions on /Applications/Sinter.app. The application bundle should be owned by root:wheel")
            }

            let operation = SignatureDatabaseOperation(path: message.binaryPath,
                                                       cachedResultOpt: cachedResultOpt,
                                                       external: queueType == OperationQueueType.secondary)

            operation.completionBlock = { [unowned operation, message, block] in
                dispatchQueue.sync {
                    if operation.isCancelled {
                        return
                    }

                    let result = operation.getResult()
                    block(message, result)

                    let binaryPath = message.binaryPath
                    self.setResult(binaryPath: binaryPath,
                                   result: result)
                }
            }

            if let parentOperation = context.operationMap[message.binaryPath] {
                operation.addDependency(parentOperation)
                
                if context.childOperationMap[message.binaryPath] == nil {
                    context.childOperationMap[message.binaryPath] = [SignatureDatabaseOperation]()
                }

                context.childOperationMap[message.binaryPath]!.append(operation)

            } else {
                context.operationMap[message.binaryPath] = operation
            }

            switch (queueType) {
            case .primary:
                context.primaryOperationQueue.addOperation(operation)

            case .secondary:
                context.secondaryOperationQueue.addOperation(operation)
            }
        }
    }

    private func setResult(binaryPath: String,
                           result: SignatureDatabaseResult) {


        context.resultCache[binaryPath] = result
        context.operationMap.removeValue(forKey: binaryPath)
        context.childOperationMap.removeValue(forKey: binaryPath)
    }

    public func invalidateCacheFor(path: String) {
        dispatchQueue.sync {
            SignatureDatabase.invalidateCacheFor(context: &context,
                                                 path: path,
                                                 logger: logger)
        }
    }

    public func invalidateCache() {
        dispatchQueue.sync {
            SignatureDatabase.invalidateCache(context: &context)
        }
    }

    static func invalidateCacheFor(context: inout SignatureDatabaseContext,
                                   path: String,
                                   logger: LoggerInterface) {

        var operationPathList = [String]()

        for it in context.childOperationMap {
            let operationPath = it.key

            if !path.starts(with: operationPath) {
                continue
            }

            operationPathList.append(operationPath)

            for operation in it.value {
                operation.cancel()

                logger.logMessage(severity: LoggerMessageSeverity.information,
                                  message: "Invalidating signature check operation for \(operationPath)")
            }
        }

        for it in context.operationMap {
            let operationPath = it.key

            if !path.starts(with: operationPath) {
                continue
            }

            operationPathList.append(operationPath)
            it.value.cancel()

            logger.logMessage(severity: LoggerMessageSeverity.information,
                              message: "Invalidating signature check operation for \(operationPath)")
        }

        for operationPath in operationPathList {
            context.childOperationMap.removeValue(forKey: operationPath)
            context.operationMap.removeValue(forKey: operationPath)
        }

        var resultPathList = [String]()

        for result in context.resultCache {
            let resultPath = result.key

            if path.starts(with: resultPath) {
                resultPathList.append(resultPath)
            }
        }

        for resultPath in resultPathList {
            context.resultCache.removeValue(forKey: resultPath)

            logger.logMessage(severity: LoggerMessageSeverity.information,
                              message: "Invalidating cached signature check status \(resultPath)")
        }
    }

    static func invalidateCache(context: inout SignatureDatabaseContext) {
        // Delete the operation maps
        context.operationMap.removeAll()
        context.childOperationMap.removeAll()

        // Cancel all the leaves first
        for operation in context.primaryOperationQueue.operations {
            let isParentOperation = operation.dependencies.isEmpty
            
            if !isParentOperation {
                operation.cancel()
            }
        }

        for operation in context.secondaryOperationQueue.operations {
            let isParentOperation = operation.dependencies.isEmpty
            
            if !isParentOperation {
                operation.cancel()
            }
        }

        // Cancel everything else
        for operation in context.primaryOperationQueue.operations {
            operation.cancel()
        }

        for operation in context.secondaryOperationQueue.operations {
            operation.cancel()
        }

        // Delete the cached results
        context.resultCache.removeAll()
    }

    static func getQueueTypeFor(fileInformation: FileInformation) -> OperationQueueType {
        if fileInformation.ownerAccountName != "root" {
            return OperationQueueType.secondary
        }
        
        if fileInformation.groupOwnerAccountName != "admin" &&
            fileInformation.groupOwnerAccountName != "staff" &&
            fileInformation.groupOwnerAccountName != "wheel" {

            return OperationQueueType.secondary
        }

        if fileInformation.directory {
            if fileInformation.path == "/Applications/Sinter.app" {
                return OperationQueueType.primary
            }

            return OperationQueueType.secondary
        }

        if fileInformation.size > fileSizeLimit {
            return OperationQueueType.secondary
        }
        
        return OperationQueueType.primary
    }

    static func getQueueTypeFor(path: String) -> OperationQueueType {
        var queueType = OperationQueueType.secondary

        if let fileInformation = getFileInformation(path: path) {
            queueType = SignatureDatabase.getQueueTypeFor(fileInformation: fileInformation)
        }
        
        return queueType
    }
}
