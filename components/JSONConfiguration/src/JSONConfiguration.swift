/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import AuthorizationManager

public struct JSONConfigurationContext {
    public var configFileURL: URL
    public var configuration = [String: [String: AnyObject]]()
    
    public init() {
        configFileURL = URL(fileURLWithPath: "")
    }
}

final class JSONConfiguration: ConfigurationInterface {
    private let dispatchQueue = DispatchQueue(label: "com.trailofbits.sinter.jsonconfiguration")
    private var updateTimer = Timer()
    private let configFilePath: String
    
    private var context = JSONConfigurationContext()

    private init(configFilePath: String) throws {
        self.configFilePath = configFilePath
        if let error = updateConfiguration() {
            throw error
        }
    }

    static func create(configFilePath: String) -> Result<ConfigurationInterface, Error> {
        Result<ConfigurationInterface, Error> { try JSONConfiguration(configFilePath: configFilePath) }
    }
    
    public func stringValue(moduleName: String, key: String) -> String? {
        var value: String?
        
        dispatchQueue.sync {
            value = JSONConfiguration.stringValue(context: context,
                                                  moduleName: moduleName,
                                                  key: key)
        }
        
        return value
    }

    public func integerValue(moduleName: String, key: String) -> Int? {
        var value: Int?
        
        dispatchQueue.sync {
            value = JSONConfiguration.integerValue(context: context,
                                                   moduleName: moduleName,
                                                   key: key)
        }
        
        return value
    }

    public func booleanValue(moduleName: String, key: String) -> Bool? {
        var value: Bool?
        
        dispatchQueue.sync {
            value = JSONConfiguration.booleanValue(context: context,
                                                   moduleName: moduleName,
                                                   key: key)
        }
        
        return value
    }

    private func updateConfiguration() -> ConfigurationError? {
        var newContext = JSONConfigurationContext()
        if let error = JSONConfiguration.loadConfigurationFromFile(context: &newContext,
                                                                   configFilePath: self.configFilePath) {
            return error
        }

        dispatchQueue.sync {
            updateTimer.invalidate()
            self.context = newContext
            
            let updateInterval: Int = JSONConfiguration.integerValue(context: self.context,
                                                                     moduleName: "Sinter",
                                                                     key: "config_update_interval") ?? 60

            updateTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(updateInterval),
                                               repeats: true) { _ in _ = self.updateConfiguration() }
        }

        return nil
    }

    static func loadConfigurationFromFile(context: inout JSONConfigurationContext,
                                          configFilePath: String) -> ConfigurationError? {

        context = JSONConfigurationContext()

        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: configFilePath) {
            return ConfigurationError.notFound
        }

        do {
            let buffer = try Data(contentsOf: URL(fileURLWithPath: configFilePath))

            var newContext = JSONConfigurationContext()
            if let error = loadConfigurationFromBuffer(context: &newContext,
                                                       configFilePath: configFilePath,
                                                       buffer: buffer) {
                return error
            }
            
            context = newContext
            return nil

        } catch {
            return ConfigurationError.invalidFormat
        }
    }
    
    static func loadConfigurationFromBuffer(context: inout JSONConfigurationContext,
                                            configFilePath: String,
                                            buffer: Data) -> ConfigurationError? {

        context = JSONConfigurationContext()

        do {
            var newContext = JSONConfigurationContext()
            newContext.configFileURL = URL(fileURLWithPath: configFilePath)
            newContext.configuration = try JSONSerialization.jsonObject(with: buffer) as! [String: [String: AnyObject]]

            context = newContext
            return nil

        } catch {
            return ConfigurationError.invalidFormat
        }
    }



    static func stringValue(context: JSONConfigurationContext,
                            moduleName: String,
                            key: String) -> String? {

        return getValue(context: context,
                        moduleName: moduleName,
                        key: key)
    }

    static func integerValue(context: JSONConfigurationContext,
                             moduleName: String,
                             key: String) -> Int? {

        return getValue(context: context,
                        moduleName: moduleName,
                        key: key)
    }

    static func booleanValue(context: JSONConfigurationContext,
                             moduleName: String,
                             key: String) -> Bool? {

        if let keyValue = stringValue(context: context,
                                      moduleName: moduleName,
                                      key: key) {

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

    private static func getValue<T>(context: JSONConfigurationContext,
                                    moduleName: String,
                                    key: String) -> T? {

        let moduleConfigurationOpt = context.configuration[moduleName]
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
