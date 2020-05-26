/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

struct JSONConfigurationContext {
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
    private var subscriptionList = [Subscription]()
    
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
    
    public func stringValue(section: String, key: String) -> String? {
        var value: String?
        
        dispatchQueue.sync {
            value = JSONConfiguration.stringValue(context: context,
                                                  section: section,
                                                  key: key)
        }
        
        return value
    }

    public func integerValue(section: String, key: String) -> Int? {
        var value: Int?
        
        dispatchQueue.sync {
            value = JSONConfiguration.integerValue(context: context,
                                                   section: section,
                                                   key: key)
        }
        
        return value
    }

    public func booleanValue(section: String, key: String) -> Bool? {
        var value: Bool?
        
        dispatchQueue.sync {
            value = JSONConfiguration.booleanValue(context: context,
                                                   section: section,
                                                   key: key)
        }
        
        return value
    }
    
    public func subscribe(subscriber: ConfigurationSubscriberInterface) -> Void {
        let subscription = Subscription(configuration: self,
                                        subscriber: subscriber)

        dispatchQueue.sync {
            subscriptionList.append(subscription)
        }
        
        subscription.notify()
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
                                                                     section: "Sinter",
                                                                     key: "config_update_interval") ?? 60

            updateTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(updateInterval),
                                               repeats: true) { _ in _ = self.updateConfiguration() }
        }

        let subscriptionList = self.subscriptionList

        for subscription in subscriptionList {
            dispatchQueue.async {
                subscription.notify()
            }
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
                            section: String,
                            key: String) -> String? {

        return getValue(context: context,
                        section: section,
                        key: key)
    }

    static func integerValue(context: JSONConfigurationContext,
                             section: String,
                             key: String) -> Int? {

        return getValue(context: context,
                        section: section,
                        key: key)
    }

    static func booleanValue(context: JSONConfigurationContext,
                             section: String,
                             key: String) -> Bool? {

        if let keyValue = stringValue(context: context,
                                      section: section,
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
                                    section: String,
                                    key: String) -> T? {

        if let section = context.configuration[section] {
            if let value = section[key] {
                if let castedValue = value as? T {
                    return castedValue
                } else {
                    return nil
                }

            } else {
                return nil
            }

        } else {
            return nil
        }
    }
}
