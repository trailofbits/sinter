/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

public enum ConfigurationError: Error {
    case unknownError
    case notFound
    case invalidFormat
}

public protocol ConfigurationSubscriberInterface : AnyObject {
    func onConfigurationChange(configuration: ConfigurationInterface) -> Void
}

public protocol ConfigurationInterface {
    func subscribe(subscriber: ConfigurationSubscriberInterface) -> Void

    func stringValue(section: String, key: String) -> String?
    func integerValue(section: String, key: String) -> Int?
    func booleanValue(section: String, key: String) -> Bool?
    func stringList(section: String, key: String) -> [String]?
}
