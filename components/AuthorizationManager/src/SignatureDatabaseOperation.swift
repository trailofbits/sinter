/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation
import DecisionManager

final class SignatureDatabaseOperation : Operation {
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

    func getPath() -> String {
        path
    }

    func getResult() -> SignatureDatabaseResult {
        result
    }
}
