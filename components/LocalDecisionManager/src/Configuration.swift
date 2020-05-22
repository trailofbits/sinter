/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import AuthorizationManager

public enum ConfigurationError: Error {
    case invalidRuleDatabasePathKey
    case invalidOrMissingAllowUnknownProgramsKey
}

public final class Configuration {
    private let allowUnknownPrograms: Bool
    private let ruleDatabasePath: String
    private let updateInterval: Int

    public init(configurationSource: ConfigurationInterface) throws {
        if let updateInterval = configurationSource.integerValue(moduleName: "LocalDecisionManager",
                                                                 key: "update_interval") {

            self.updateInterval = updateInterval
        } else {
            self.updateInterval = 60
        }

        if let ruleDatabasePath = configurationSource.stringValue(moduleName: "LocalDecisionManager",
                                                                  key: "rule_database_path") {
            self.ruleDatabasePath = ruleDatabasePath

        } else {
            throw ConfigurationError.invalidRuleDatabasePathKey
        }

        if let allowUnknownPrograms = configurationSource.booleanValue(moduleName: "LocalDecisionManager",
                                                                       key: "allow_unknown_programs") {
            self.allowUnknownPrograms = allowUnknownPrograms

        } else {
            throw ConfigurationError.invalidOrMissingAllowUnknownProgramsKey
        }
    }

    public func unknownProgramsAllowed() -> Bool {
      return allowUnknownPrograms
    }

    public func databasePath() -> String {
      return ruleDatabasePath
    }

    public func configurationUpdateInterval() -> Int {
      return updateInterval
    }
}
