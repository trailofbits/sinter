/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import AuthorizationManager

private final class JSONConfiguration: ConfigurationInterface {
    private let configuration: [String: [String: AnyObject]]

    private init(configFilePath: String) throws {
        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: configFilePath) {
            throw ConfigurationError.notFound
        }

        let configFileURL = URL(fileURLWithPath: configFilePath)

        do {
            let jsonData = try Data(contentsOf: configFileURL)
            configuration = try JSONSerialization.jsonObject(with: jsonData) as! [String: [String: AnyObject]]

        } catch {
            throw ConfigurationError.invalidFormat
        }
    }

    static func create(configFilePath: String) -> Result<ConfigurationInterface, Error> {
        Result<ConfigurationInterface, Error> { try JSONConfiguration(configFilePath: configFilePath) }
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

    public func booleanValue(moduleName: String, key: String) -> Bool? {
        if let keyValue = stringValue(moduleName: moduleName, key: key) {
            if keyValue == "true" {
                return true
            } else if keyValue == "false" {
                return false
            } else {
                return nil
            }

        } else {
            return nil
        }
    }
}

public func createJSONConfiguration() -> Result<ConfigurationInterface, Error> {
    let etcFolderList: [String] = [
        "/etc",
        "/usr/local/etc",
    ]

    var configurationObjectOpt: ConfigurationInterface?

    for etcFolder in etcFolderList {
        let configFilePath = etcFolder + "/sinter/config.json"

        let jsonConfigurationExp = JSONConfiguration.create(configFilePath: configFilePath)
        switch jsonConfigurationExp {
        case let .success(obj):
            configurationObjectOpt = obj

        case let .failure(error):
            print("\(configFilePath): \(error)")
        }

        if configurationObjectOpt != nil {
            break
        }
    }

    if let configurationObject = configurationObjectOpt {
        return .success(configurationObject)

    } else {
        return .failure(ConfigurationError.notFound)
    }
}
