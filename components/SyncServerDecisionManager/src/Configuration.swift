/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import AuthorizationManager
import Configuration

public enum ConfigurationError: Error {
    case invalidOrMissingAllowUnknownProgramsKey
    case invalidServerAddressKey
    case invalidMachineIdentifierKey
}

public final class Configuration {
    private let allowUnknownPrograms: Bool
    private let serverURL: String
    private let machineIdentifier: String
    private let updateInterval: Int

    public init(configurationSource: ConfigurationInterface) throws {
        if let allowUnknownPrograms = configurationSource.booleanValue(section: "SyncServerDecisionManager",
                                                                       key: "allow_unknown_programs") {
            self.allowUnknownPrograms = allowUnknownPrograms

        } else {
            throw ConfigurationError.invalidOrMissingAllowUnknownProgramsKey
        }

        if let serverURL = configurationSource.stringValue(section: "SyncServerDecisionManager",
                                                           key: "server_address") {
            self.serverURL = serverURL

        } else {
            throw ConfigurationError.invalidServerAddressKey
        }

        if let machineIdentifier = configurationSource.stringValue(section: "SyncServerDecisionManager",
                                                                   key: "machine_identifier") {
            self.machineIdentifier = machineIdentifier

        } else {
            throw ConfigurationError.invalidMachineIdentifierKey
        }

        if let updateInterval = configurationSource.integerValue(section: "SyncServerDecisionManager",
                                                                 key: "update_interval") {

            self.updateInterval = updateInterval
        } else {
            self.updateInterval = 60
        }
    }

    public func unknownProgramsAllowed() -> Bool {
      return allowUnknownPrograms
    }

    public func serverAddress() -> String {
      return serverURL
    }

    public func machineId() -> String {
        return machineIdentifier
    }

    public func configurationUpdateInterval() -> Int {
      return updateInterval
    }
}
