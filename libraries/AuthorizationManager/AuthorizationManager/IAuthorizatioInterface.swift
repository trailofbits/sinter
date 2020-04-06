/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public struct IAuthorizationInterfaceRequest {
    public var binaryPath: String
    public var cdhash: String
    public var signingId: String
    public var teamId: String
    public var isAppleSigned: Bool
}

public protocol IAuthorizationInterface {
    func ruleForBinary(request: IAuthorizationInterfaceRequest, allow: inout Bool, cache: inout Bool) -> Bool
}
