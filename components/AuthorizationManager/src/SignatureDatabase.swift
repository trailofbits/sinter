/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation
import EndpointSecurityClient

fileprivate let fileSizeLimit: Int = (1024 * 1024) * 10

public enum SignatureDatabaseResult {
    case Valid
    case Invalid
    case NotSigned
    case Failed
}

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

    public func checkSignatureFor(message: EndpointSecurityExecAuthorization,
                                  block: @escaping SignatureDatabaseCallback) {

        let fileInformationOpt = getFileInformation(path: message.binaryPath)

        dispatchQueue.sync {
            SignatureDatabase.checkSignatureFor(context: &context,
                                                message: message,
                                                fileInformationOpt: fileInformationOpt,
                                                block: block)
        }
    }

    public func invalidateCacheFor(path: String) {
        dispatchQueue.sync {
            SignatureDatabase.invalidateCacheFor(context: &context,
                                                 path: path)
        }
    }

    public func invalidateCache() {
        dispatchQueue.sync {
            SignatureDatabase.invalidateCache(context: &context)
        }
    }

    static func invalidateCacheFor(context: inout SignatureDatabaseContext,
                                   path: String) {

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
        }
    }

    static func invalidateCache(context: inout SignatureDatabaseContext) {
        for operation in context.operationMap {
            operation.value.cancel()
        }

        context.operationMap.removeAll()
        context.resultCache.removeAll()
    }

    static func checkSignatureFor(context: inout SignatureDatabaseContext,
                                  message: EndpointSecurityExecAuthorization,
                                  fileInformationOpt: FileInformation?,
                                  block: @escaping SignatureDatabaseCallback) {

        var queueTypeOpt: OperationQueueType? = nil
        if let fileInformation = fileInformationOpt {
            if fileInformation.ownerId == 0 && fileInformation.size < fileSizeLimit {
                queueTypeOpt = OperationQueueType.primary
            } else {
                queueTypeOpt = OperationQueueType.secondary
            }
        }

        if queueTypeOpt == nil {
            context.resultCache[message.binaryPath] = SignatureDatabaseResult.Failed
            queueTypeOpt = OperationQueueType.secondary

        } else if message.codeDirectoryHash.hash.isEmpty {
            context.resultCache[message.binaryPath] = SignatureDatabaseResult.NotSigned
        }

        let cachedResultOpt = context.resultCache[message.binaryPath]
        let operation = SignatureDatabaseOperation(path: message.binaryPath,
                                                   cachedResultOpt: cachedResultOpt)

        operation.completionBlock = { [unowned operation, message, block, context] in
            dispatchQueue.sync {
                context.resultCache[message.binaryPath] = operation.getResult()
                block(message, operation.getResult())

                context.operationMap.removeValue(forKey: message.binaryPath)
            }
        }

        let parentOperationOpt = context.operationMap[message.binaryPath]
        if parentOperationOpt != nil {
            operation.addDependency(parentOperationOpt!)
        }

        context.operationMap[message.binaryPath] = operation

        switch (queueTypeOpt!) {
        case .primary:
            context.primaryOperationQueue.addOperation(operation)

        case .secondary:
            context.secondaryOperationQueue.addOperation(operation)
        }
    }
}
