/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import AuthorizationManager
import CodeSigningUtils
import Dispatch
import Foundation

final class SignatureDatabase: ISignatureDatabase {
    private let operationQueue = OperationQueue()
    private let dispatchQueue = DispatchQueue(label: "")
    private var operationMap = [String: SignatureDatabaseOperation]()
    private var valueCache = [String: Bool]()

    public init(concurrentOperationCount: Int) {
        operationQueue.maxConcurrentOperationCount = concurrentOperationCount
        operationQueue.qualityOfService = .userInteractive
    }

    public func checkSignatureFor(message: IEndpointSecurityClientMessage,
                                  block: @escaping (_ message: IEndpointSecurityClientMessage, _ valid: Bool) -> Void) {
        dispatchQueue.sync {
            if let cachedValue = valueCache[message.binaryPath] {
                self.operationMap.removeValue(forKey: message.binaryPath)
                block(message, cachedValue)

            } else {
                let operation = SignatureDatabaseOperation(path: message.binaryPath)
                operation.completionBlock = { [unowned operation, message, block] in
                    block(message, operation.isValid())

                    self.dispatchQueue.sync {
                        self.valueCache[message.binaryPath] = operation.isValid()
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
    }

    public func invalidateCacheFor(path _: String) {}
}

private final class SignatureDatabaseOperation: Operation {
    private let path: String
    private var valid: Bool = false

    public init(path: String) {
        self.path = path
        super.init()
    }

    public override func main() {
        guard !isCancelled else { return }

        if let parentOperation = dependencies.first as? SignatureDatabaseOperation {
            valid = parentOperation.isValid()

        } else {
            let err = checkCodeSignature(path: path)
            valid = (err == CodeSignatureStatus.valid)
        }
    }

    public func getPath() -> String {
        path
    }

    public func isValid() -> Bool {
        valid
    }
}
