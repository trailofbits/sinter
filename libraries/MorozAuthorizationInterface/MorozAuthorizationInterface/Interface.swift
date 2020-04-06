/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import AuthorizationManager
import Configuration
import Foundation
import Logger

public func createMorozAuthorizationInterface(logger: ILogger,
                                              configuration: IConfiguration) -> IAuthorizationInterface? {
    let serverAddressOpt = configuration.stringValue(moduleName: "MorozAuthorizationInterface",
                                                     key: "server_address")

    if serverAddressOpt == nil {
        logger.logMessage(severity: LogMessageSeverity.error,
                          message: "Configuration key missing: MorozAuthorizationInterface.server_address")

        return nil
    }

    let updateIntervalOpt = configuration.integerValue(moduleName: "MorozAuthorizationInterface",
                                                       key: "update_interval")

    if updateIntervalOpt == nil {
        logger.logMessage(severity: LogMessageSeverity.error,
                          message: "Configuration key missing: MorozAuthorizationInterface.update_interval")

        return nil
    }

    let updateInterval = TimeInterval(updateIntervalOpt!)

    let defaultActionOpt = configuration.stringValue(moduleName: "MorozAuthorizationInterface",
                                                     key: "default_action")

    if defaultActionOpt == nil {
        logger.logMessage(severity: LogMessageSeverity.error,
                          message: "Configuration key missing: MorozAuthorizationInterface.default_action")

        return nil
    }

    let defaultAllow: Bool
    if defaultActionOpt! == "allow" {
        defaultAllow = true

    } else if defaultActionOpt! == "deny" {
        defaultAllow = false

    } else {
        logger.logMessage(severity: LogMessageSeverity.error,
                          message: "Invalid configuration key value: MorozAuthorizationInterface.default_action. Valid values are 'allow' or 'deny'")

        return nil
    }

    return MorozAuthorizationInterface(logger: logger,
                                       serverAddress: serverAddressOpt!,
                                       configUpdateInterval: updateInterval,
                                       defaultAllow: defaultAllow)
}
