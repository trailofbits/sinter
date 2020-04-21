/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import LibSinter

private final class SyncServerDecisionManager: DecisionManagerInterface {
    private let logger: LoggerInterface
    private let configuration: ConfigurationInterface

    private let serverAddress: String
    private let machineIdentifier: String
    private let defaultAllow: Bool

    private var ruleDatabaseUpdateTimer = Timer()
    private var ruleDatabase = RuleDatabase()

    private init(logger: LoggerInterface,
                 configuration: ConfigurationInterface) throws {
        self.logger = logger
        self.configuration = configuration

        var configUpdateIntervalOpt = configuration.integerValue(moduleName: "SyncServerDecisionManager",
                                                                 key: "update_interval")

        if configUpdateIntervalOpt == nil {
            configUpdateIntervalOpt = 10
        }

        if let machineIdentifier = configuration.stringValue(moduleName: "SyncServerDecisionManager",
                                                             key: "machine_identifier") {
            self.machineIdentifier = machineIdentifier

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'machine_identifier' setting is missing from the 'SyncServerDecisionManager' configuration section")

            throw DecisionManagerError.invalidConfiguration
        }

        if let defaultAction = configuration.stringValue(moduleName: "SyncServerDecisionManager",
                                                         key: "default_action") {
            if defaultAction == "allow" {
                defaultAllow = true

            } else if defaultAction == "deny" {
                defaultAllow = false

            } else {
                logger.logMessage(severity: LoggerMessageSeverity.error,
                                  message: "The 'SyncServerDecisionManager.default_action' setting is not valid. Allowed values are: 'allow', 'deny'")

                throw DecisionManagerError.invalidConfiguration
            }

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'default_action' setting is missing from the 'SyncServerDecisionManager' configuration section")

            throw DecisionManagerError.invalidConfiguration
        }

        if let serverAddress = configuration.stringValue(moduleName: "SyncServerDecisionManager",
                                                         key: "server_address") {
            self.serverAddress = serverAddress

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'server_address' setting is missing from the 'SyncServerDecisionManager' configuration section")

            throw DecisionManagerError.invalidConfiguration
        }

        ruleDatabaseUpdateTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(configUpdateIntervalOpt!),
                                                       repeats: true) { _ in self.requestRuleDatabaseUpdate() }

        ruleDatabaseUpdateTimer.fire()
    }

    public func processRequest(request: DecisionManagerRequest,
                               allow: inout Bool) -> Bool {
        if request.platformBinary {
            allow = true

        } else if let rule = ruleDatabase.binaryRuleMap[request.codeDirectoryHash.hash] {
            allow = rule.policy == RulePolicy.whitelist

        } else {
            allow = defaultAllow
        }

        return true
    }

    static func create(logger: LoggerInterface,
                       configuration: ConfigurationInterface) -> Result<DecisionManagerInterface, Error> {
        Result<DecisionManagerInterface, Error> { try SyncServerDecisionManager(logger: logger,
                                                                                configuration: configuration) }
    }

    private func requestRuleDatabaseUpdate() {
        logger.logMessage(severity: LoggerMessageSeverity.information,
                          message: "Requesting new rule database from the sync-server...")

        let requestAddress = serverAddress + "/v1/santa/ruledownload/" + machineIdentifier

        var request = URLRequest(url: URL(string: requestAddress)!)
        request.httpMethod = "POST"

        let session = URLSession.shared
        let task = session.dataTask(with: request, completionHandler: { dataOpt, _, errorOpt -> Void in
            if let error = errorOpt {
                let errorMessage = "Failed to contact the Moroz server: " + error.localizedDescription

                self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                       message: errorMessage)

                return
            }

            if let data = dataOpt {
                let newRuleDatabase = parseJSONRuleDatabase(jsonData: data)

                var acceptRules = false
                switch newRuleDatabase.status {
                case RuleDatabaseStatus.invalid:
                    self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                           message: "The rule database received from the sync-server is not valid")

                case RuleDatabaseStatus.partial:
                    acceptRules = true

                    self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                           message: "The rule database received from the sync-server contained invalid rules")

                case RuleDatabaseStatus.valid:
                    acceptRules = true
                }

                if acceptRules {
                    self.ruleDatabase = newRuleDatabase
                }

            } else {
                self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                       message: "The sync-server has not answered to the POST request")
            }
        })

        task.resume()
    }
}

public func createSyncServerDecisionManager(logger: LoggerInterface,
                                            configuration: ConfigurationInterface) -> Result<DecisionManagerInterface, Error> {
    SyncServerDecisionManager.create(logger: logger,
                                     configuration: configuration)
}
