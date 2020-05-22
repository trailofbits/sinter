/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public enum ConfigurationError: Error {
    case unknownError
    case notFound
    case invalidFormat
}

public protocol ConfigurationInterface {
    func stringValue(moduleName: String, key: String) -> String?
    func integerValue(moduleName: String, key: String) -> Int?
    func booleanValue(moduleName: String, key: String) -> Bool?
}
