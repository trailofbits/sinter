/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import SystemExtensions

enum SystemExtensionInstallerOperation {
    case install
    case uninstall
}

final class SystemExtensionInstaller: NSObject, OSSystemExtensionRequestDelegate {
    private let operation: SystemExtensionInstallerOperation
    private let request: OSSystemExtensionRequest

    public init(operation: SystemExtensionInstallerOperation) {
        self.operation = operation

        switch self.operation {
        case .install:
            request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: "com.trailofbits.sinter",
                                                                 queue: DispatchQueue.global())

        case .uninstall:
            request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: "com.trailofbits.sinter",
                                                                   queue: DispatchQueue.global())
        }

        super.init()

        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    public func request(_: OSSystemExtensionRequest,
                        actionForReplacingExtension _: OSSystemExtensionProperties,
                        withExtension _: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        print("Inside callback 1")
        return OSSystemExtensionRequest.ReplacementAction.replace
    }

    public func requestNeedsUserApproval(_: OSSystemExtensionRequest) {
        print("Inside callback 2")
    }

    public func request(_: OSSystemExtensionRequest,
                        didFinishWithResult _: OSSystemExtensionRequest.Result) {
        print("Inside callback 3")
        exit(EXIT_SUCCESS)
    }

    public func request(_: OSSystemExtensionRequest,
                        didFailWithError error: Error) {
        print("Inside callback 4: \(error)")
        DispatchQueue.main.async {
            exit(EXIT_FAILURE)
        }
    }
}
