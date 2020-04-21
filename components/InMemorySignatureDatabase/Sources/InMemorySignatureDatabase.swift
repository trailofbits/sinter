/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import LibSinter

private final class InMemorySignatureDatabase: SignatureDatabaseInterface {
    private let operationQueue = OperationQueue()
    private let dispatchQueue = DispatchQueue(label: "")
    private var operationMap = [String: SignatureDatabaseOperation]()
    private var resultCache = [String: SignatureDatabaseResult]()

    private init() throws {
        // Initialize the operation queue according to the online processor count
        let onlineProcessorCount = sysconf(CInt(_SC_NPROCESSORS_ONLN))
        operationQueue.maxConcurrentOperationCount = onlineProcessorCount
        operationQueue.qualityOfService = .userInteractive
    }

    static func create() -> Result<SignatureDatabaseInterface, Error> {
        Result<SignatureDatabaseInterface, Error> { try InMemorySignatureDatabase() }
    }

    public func checkSignatureFor(message: EndpointSecurityExecAuthorization,
                                  block: @escaping SignatureDatabaseCallback) {
        dispatchQueue.sync {
            var cachedResultOpt: SignatureDatabaseResult?
            if message.codeDirectoryHash.hash.isEmpty {
                resultCache[message.binaryPath] = SignatureDatabaseResult.NotSigned
            }

            if let cachedResult = resultCache[message.binaryPath] {
                cachedResultOpt = cachedResult
            }

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

            self.operationQueue.addOperation(operation)
            self.operationMap[message.binaryPath] = operation
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

public func createInMemorySignatureDatabase() -> Result<SignatureDatabaseInterface, Error> {
    InMemorySignatureDatabase.create()
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
