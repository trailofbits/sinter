/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import AuthorizationManager

public enum ConfigurationError: Error {
    case invalidAllowUnsignedPrograms
}

public final class Configuration {
    private let allowUnsignedPrograms: Bool
    private let updateInterval: Int

    public init(configurationSource: ConfigurationInterface) throws {
        if let updateInterval = configurationSource.integerValue(moduleName: "EndpointSecurityClient",
                                                                 key: "update_interval") {

            self.updateInterval = updateInterval
        } else {
            self.updateInterval = 60
        }

        if let allowUnsignedPrograms = configurationSource.booleanValue(moduleName: "EndpointSecurityClient",
                                                                        key: "allow_unsigned") {
            self.allowUnsignedPrograms = allowUnsignedPrograms

        } else {
            throw ConfigurationError.invalidAllowUnsignedPrograms
        }
    }

    public func unsignedProgramsAllowed() -> Bool {
      return allowUnsignedPrograms
    }

    public func configurationUpdateInterval() -> Int {
      return updateInterval
    }
}
