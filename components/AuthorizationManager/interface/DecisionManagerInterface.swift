/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public enum DecisionManagerError: Error {
    case unknownError
    case invalidConfiguration
}

public enum DecisionManagerClientMode: Int {
    case MONITOR
    case LOCKDOWN
}

public struct DecisionManagerRequest {
    public var binaryPath: String
    public var codeDirectoryHash: BinaryHash
    public var signingIdentifier: String
    public var teamIdentifier: String
    public var platformBinary: Bool
}

public protocol DecisionManagerInterface {
    func processRequest(request: DecisionManagerRequest,
                        allow: inout Bool) -> Bool
    func getClientMode() -> DecisionManagerClientMode
}
