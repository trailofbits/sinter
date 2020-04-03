/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import AuthorizationManager
import Foundation
import Logger

public func createMorozAuthorizationInterface(logger: ILogger) -> IAuthorizationInterface? {
    MorozAuthorizationInterface(logger: logger, serverAddress: "http://127.0.0.1:8080", configUpdateInterval: 60)
}
