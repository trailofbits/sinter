/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public struct IAuthorizationInterfaceRequest {
    public var binaryPath: String = ""
    public var teamId: String = ""

    public init(binaryPath: String, teamId: String) {
        self.binaryPath = binaryPath
        self.teamId = teamId
    }
}

public protocol IAuthorizationInterface {
    func ruleForBinary(request: IAuthorizationInterfaceRequest, allow: inout Bool, cache: inout Bool) -> Bool
}
