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

public typealias SignatureDatabaseCallback = (EndpointSecurityExecAuthorization, SignatureDatabaseResult) -> Void

final class SignatureDatabase {
    private let primaryOperationQueue: OperationQueue
    private let secondaryOperationQueue: OperationQueue

    private let dispatchQueue = DispatchQueue(label: "")
    private var operationMap = [String: SignatureDatabaseOperation]()
    private var resultCache = [String: SignatureDatabaseResult]()

    init() {
        primaryOperationQueue = createOperationQueue(type: OperationQueueType.primary)
        secondaryOperationQueue = createOperationQueue(type: OperationQueueType.secondary)
    }

    public func checkSignatureFor(message: EndpointSecurityExecAuthorization,
                                  block: @escaping SignatureDatabaseCallback) {

        var queueTypeOpt: OperationQueueType? = nil
        if let fileInformation = getFileInformation(path: message.binaryPath) {
            // TODO: Check file permissions
            if fileInformation.ownerId == 0 && fileInformation.size < fileSizeLimit {
                queueTypeOpt = OperationQueueType.primary
            } else {
                queueTypeOpt = OperationQueueType.secondary
            }
        }

        dispatchQueue.sync {
            if queueTypeOpt == nil {
                resultCache[message.binaryPath] = SignatureDatabaseResult.Invalid
                queueTypeOpt = OperationQueueType.secondary

            } else if message.codeDirectoryHash.hash.isEmpty {
                resultCache[message.binaryPath] = SignatureDatabaseResult.NotSigned
            }

            let cachedResultOpt = resultCache[message.binaryPath]
            let operation = SignatureDatabaseOperation(path: message.binaryPath,
                                                       cachedResultOpt: cachedResultOpt)

            operation.completionBlock = { [unowned operation, message, block] in
                self.dispatchQueue.sync {
                    self.resultCache[message.binaryPath] = operation.getResult()
                    block(message, operation.getResult())

                    self.operationMap.removeValue(forKey: message.binaryPath)
                }
            }

            let parentOperationOpt = self.operationMap[message.binaryPath]
            if parentOperationOpt != nil {
                operation.addDependency(parentOperationOpt!)
            }

            self.operationMap[message.binaryPath] = operation

            switch (queueTypeOpt!) {
            case .primary:
                self.primaryOperationQueue.addOperation(operation)
            case .secondary:
                self.secondaryOperationQueue.addOperation(operation)
            }
        }
    }

    public func invalidateCacheFor(path: String) {
        dispatchQueue.sync {
            for operation in operationMap {
                let operationPath = operation.value.getPath()
                if path.starts(with: operationPath) {
                    operation.value.cancel()
                    operationMap.removeValue(forKey: operationPath)
                }
            }

            for result in resultCache {
                let resultPath = result.key

                if path.starts(with: resultPath) {
                    resultCache.removeValue(forKey: resultPath)
                }
            }
        }
    }

    public func invalidateCache() {
        dispatchQueue.sync {
            for operation in operationMap {
                operation.value.cancel()
            }

            operationMap.removeAll()
            resultCache.removeAll()
        }
    }
}

private final class SignatureDatabaseOperation: Operation {
    private let path: String
    private var result = SignatureDatabaseResult.Invalid
    private let cachedResultOpt: SignatureDatabaseResult?

    public init(path: String,
                cachedResultOpt: SignatureDatabaseResult?) {
        self.path = path
        self.cachedResultOpt = cachedResultOpt

        super.init()
    }

    public override func main() {
        guard !isCancelled else { return }

        if let cachedResult = cachedResultOpt {
            result = cachedResult
            return
        }

        if let parentOperation = dependencies.first as? SignatureDatabaseOperation {
            result = parentOperation.getResult()

        } else {
            switch checkCodeSignature(path: path) {
            case .internalError:
                result = SignatureDatabaseResult.Failed

            case .ioError:
                result = SignatureDatabaseResult.Failed

            case .valid:
                result = SignatureDatabaseResult.Valid

            case .invalid:
                result = SignatureDatabaseResult.Invalid
            }
        }
    }

    public func getPath() -> String {
        path
    }

    public func getResult() -> SignatureDatabaseResult {
        result
    }
}
