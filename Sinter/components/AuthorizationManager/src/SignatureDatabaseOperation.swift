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
    private let external: Bool

    public init(path: String,
                cachedResultOpt: SignatureDatabaseResult?,
                external: Bool) {

        self.path = path
        self.cachedResultOpt = cachedResultOpt
        self.external = external

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
            return
        }
        
        if external {
            externalSignatureCheck()
        } else {
            inProcessSignatureCheck()
        }
    }
    
    private func inProcessSignatureCheck() {
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

    private func externalSignatureCheck() {
        result = SignatureDatabaseResult.Failed

        do {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/Applications/Sinter.app/Contents/MacOS/signature-checker")
            process.arguments = [self.path]

            try process.run()

            while process.isRunning {
                sleep(1)

                if isCancelled {
                    process.terminate()
                    break
                }
            }

            if isCancelled {
                return
            }

            if process.terminationStatus == 0 {
                result = SignatureDatabaseResult.Valid
            } else {
                result = SignatureDatabaseResult.Invalid
            }

        } catch {
        }
    }

    func getPath() -> String {
        path
    }

    func getResult() -> SignatureDatabaseResult {
        result
    }
}
