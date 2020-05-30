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
    var resultCache = [String: SignatureDatabaseResult]()

    let primaryOperationQueue = createOperationQueue(type: OperationQueueType.primary)
    let secondaryOperationQueue = createOperationQueue(type: OperationQueueType.secondary)
}

fileprivate let dispatchQueue = DispatchQueue(label: "com.trailofbits.sinter.signature-database")

final class SignatureDatabase {
    private var context = SignatureDatabaseContext()
    private var logger: LoggerInterface

    public init(logger: LoggerInterface) {
        self.logger = logger
    }

    public func checkSignatureFor(message: EndpointSecurityExecAuthorization,
                                  block: @escaping SignatureDatabaseCallback) {

        dispatchQueue.sync {
            let fileInformationOpt = getFileInformation(path: message.binaryPath)

            var queueType = OperationQueueType.secondary
            if let fileInformation = fileInformationOpt {
                if fileInformation.ownerId == 0 && fileInformation.size < fileSizeLimit {
                    queueType = OperationQueueType.primary
                }

            } else {
                context.resultCache[message.binaryPath] = SignatureDatabaseResult.Failed
            }

            if message.codeDirectoryHash.hash.isEmpty {
                context.resultCache[message.binaryPath] = SignatureDatabaseResult.NotSigned
            }

            let cachedResultOpt = context.resultCache[message.binaryPath]
            let operation = SignatureDatabaseOperation(path: message.binaryPath,
                                                       cachedResultOpt: cachedResultOpt)

            operation.completionBlock = { [unowned operation, message, block] in
                let result = operation.getResult()
                block(message, result)

                let binaryPath = message.binaryPath
                self.setResult(binaryPath: binaryPath,
                               result: result)
            }

            let parentOperationOpt = context.operationMap[message.binaryPath]
            if parentOperationOpt != nil {
                operation.addDependency(parentOperationOpt!)
            }

            context.operationMap[message.binaryPath] = operation

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

        dispatchQueue.sync {
            context.resultCache[binaryPath] = result
            context.operationMap.removeValue(forKey: binaryPath)
        }
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

        for operation in context.operationMap {
            let operationPath = operation.value.getPath()

            if !path.starts(with: operationPath) {
                continue
            }

            operationPathList.append(operationPath)
            operation.value.cancel()
        }
        
        for operationPath in operationPathList {
            context.operationMap.removeValue(forKey: operationPath)

            logger.logMessage(severity: LoggerMessageSeverity.information,
                              message: "Invalidating signature check operation for \(operationPath)")
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
        for operation in context.operationMap {
            operation.value.cancel()
        }

        context.operationMap.removeAll()
        context.resultCache.removeAll()
    }
}
