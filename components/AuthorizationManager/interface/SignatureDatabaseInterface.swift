/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public enum SignatureDatabaseError: Error {
    case unknownError
}

public enum SignatureDatabaseResult {
    case Valid
    case Invalid
    case NotSigned
    case Failed
}

public typealias SignatureDatabaseCallback = (EndpointSecurityExecAuthorization, SignatureDatabaseResult) -> Void

public protocol SignatureDatabaseInterface {
    func checkSignatureFor(message: EndpointSecurityExecAuthorization,
                           block: @escaping SignatureDatabaseCallback)

    func invalidateCacheFor(path: String)

    func invalidateCache()
}
