/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import AuthorizationManager
import Logger
import Configuration

private final class SyncServerDecisionManager: DecisionManagerInterface {
    private let logger: LoggerInterface
    private let configurationSource: ConfigurationInterface
    private var configuration: Configuration

    private var configUpdateTimer = Timer()

    private var ruleDatabase = RuleDatabase()

    private init(logger: LoggerInterface,
                 configurationSource: ConfigurationInterface) throws {

        self.logger = logger
        self.configurationSource = configurationSource

        // Make sure that at least the very first configuration succeeds, since we
        // always revert to the last known good configuration if the the file breaks
        // later on when we do an update
        if let configuration = SyncServerDecisionManager.readConfiguration(configurationSource: self.configurationSource,
                                                                           logger: self.logger) {
            self.configuration = configuration
        } else {
            throw DecisionManagerError.invalidConfiguration
        }

        self.requestRuleDatabaseUpdate()

        configUpdateTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(self.configuration.configurationUpdateInterval()),
                                                 repeats: true) { _ in
                                                    if let newConfiguration = SyncServerDecisionManager.readConfiguration(configurationSource: self.configurationSource, logger: self.logger) {
                                                        self.configuration = newConfiguration
                                                    }

                                                    self.requestRuleDatabaseUpdate()
                                                }
    }

    public func processRequest(request: DecisionManagerRequest,
                               allow: inout Bool) -> Bool {
        if request.platformBinary {
            allow = true

        } else if let rule = ruleDatabase.binaryRuleMap[request.codeDirectoryHash.hash] {
            allow = rule.policy == RulePolicy.whitelist

        } else {
            allow = self.configuration.unknownProgramsAllowed()
        }

        return true
    }

    static func create(logger: LoggerInterface,
                       configuration: ConfigurationInterface) -> Result<DecisionManagerInterface, Error> {
        Result<DecisionManagerInterface, Error> { try SyncServerDecisionManager(logger: logger,
                                                                                configurationSource: configuration) }
    }

    private static func readConfiguration(configurationSource: ConfigurationInterface,
                                          logger: LoggerInterface) -> Configuration? {

        do {
            return try Configuration(configurationSource: configurationSource)

        } catch ConfigurationError.invalidServerAddressKey {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'server_address' key is missing from the SyncServerDecisionManager section")

            return nil

        } catch ConfigurationError.invalidOrMissingAllowUnknownProgramsKey {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'allow_unknown_programs' key is missing from the SyncServerDecisionManager section")

            return nil

        } catch ConfigurationError.invalidMachineIdentifierKey {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'machine_identifier' key is missing from the SyncServerDecisionManager section")

            return nil

        } catch {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                               message: "Unexpected error occurred when attempting to acquire the SyncServerDecisionManager configuration")

            return nil
        }
    }

    private func requestRuleDatabaseUpdate() {
        logger.logMessage(severity: LoggerMessageSeverity.information,
                          message: "Requesting new rule database from the sync-server...")

        let requestAddress = configuration.serverAddress() +
                             "/v1/santa/ruledownload/" +
                             configuration.machineId()

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
