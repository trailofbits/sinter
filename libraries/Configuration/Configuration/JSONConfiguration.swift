/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

final class JSONConfiguration: IConfiguration {
    private let configuration: [String: [String: AnyObject]]

    public init?(configFilePath: String) {
        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: configFilePath) {
            return nil
        }

        let configFileURL = URL(fileURLWithPath: configFilePath)

        do {
            let jsonData = try Data(contentsOf: configFileURL)
            configuration = try JSONSerialization.jsonObject(with: jsonData) as! [String: [String: AnyObject]]

        } catch {
            return nil
        }
    }

    private func getValue<T>(moduleName: String, key: String) -> T? {
        let moduleConfigurationOpt = configuration[moduleName]
        if moduleConfigurationOpt == nil {
            return nil
        }

        let moduleConfiguration = moduleConfigurationOpt!

        let valueOpt = moduleConfiguration[key]
        if valueOpt == nil {
            return nil
        }

        let value = valueOpt!

        if let castedValue = value as? T {
            return castedValue
        } else {
            return nil
        }
    }

    public func stringValue(moduleName: String, key: String) -> String? {
        getValue(moduleName: moduleName, key: key)
    }

    public func integerValue(moduleName: String, key: String) -> Int? {
        getValue(moduleName: moduleName, key: key)
    }
}
