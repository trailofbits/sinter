/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation
import Logger

public func createAuthorizationManager(authorizationInterface: IAuthorizationInterface,
                                       signatureDatabase: ISignatureDatabase,
                                       endpointSecurityClient: IEndpointSecurityClient,
                                       logger: ILogger,
                                       concurrentOperationCount: Int) -> IAuthorizationManager? {
    AuthorizationManager(authorizationInterface: authorizationInterface,
                         signatureDatabase: signatureDatabase,
                         endpointSecurityClient: endpointSecurityClient,
                         logger: logger,
                         concurrentOperationCount: concurrentOperationCount)
}
