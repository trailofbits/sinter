/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import AuthorizationManager
import Foundation
import Logger

public func createEndpointSecurityClient(logger: ILogger) -> IEndpointSecurityClient? {
    EndpointSecurityClient(logger: logger)
}
