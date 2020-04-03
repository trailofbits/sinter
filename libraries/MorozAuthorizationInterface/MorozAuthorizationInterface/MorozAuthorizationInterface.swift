/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import AuthorizationManager
import Logger

class MorozAuthorizationInterface: IAuthorizationInterface {
    private let logger: ILogger

    private let serverAddress: String
    private let configUpdateInterval: TimeInterval
    private let machineIdentifier: String

    private var ruleDatabaseUpdateTimer = Timer()
    private var ruleDatabase = RuleDatabase()

    public init?(logger: ILogger, serverAddress: String, configUpdateInterval: TimeInterval) {
        self.logger = logger
        self.serverAddress = serverAddress

        // TODO: update the rule database every configUpdateInterval seconds
        self.configUpdateInterval = configUpdateInterval

        // TODO: this should be a unique identifier that is hard to guess
        machineIdentifier = "Sinter"

        // Request the rules right now, then schedule new updates
        requestRuleDatabaseUpdate()

        ruleDatabaseUpdateTimer = Timer.scheduledTimer(withTimeInterval: self.configUpdateInterval,
                                                       repeats: true) { _ in self.requestRuleDatabaseUpdate() }
    }

    deinit {
        self.ruleDatabaseUpdateTimer.invalidate()
    }

    public func ruleForBinary(request _: IAuthorizationInterfaceRequest, allow: inout Bool, cache: inout Bool) -> Bool {
        // TODO: Authorize using self.binaryRuleMap and self.certificateRuleMap
        allow = true
        cache = true

        return true
    }

    private func requestRuleDatabaseUpdate() {
        let requestAddress = serverAddress + "/v1/santa/ruledownload/" + machineIdentifier

        var request = URLRequest(url: URL(string: requestAddress)!)
        request.httpMethod = "POST"

        let session = URLSession.shared
        let task = session.dataTask(with: request, completionHandler: { dataOpt, _, errorOpt -> Void in
            if let error = errorOpt {
                let errorMessage = "Failed to contact the Moroz server: " + error.localizedDescription

                self.logger.logMessage(severity: LogMessageSeverity.error,
                                       message: errorMessage)

                return
            }

            if let data = dataOpt {
                let newRuleDatabase = parseJSONRuleDatabase(jsonData: data)

                var acceptRules = false
                switch newRuleDatabase.status {
                case RuleDatabaseStatus.invalid:
                    self.logger.logMessage(severity: LogMessageSeverity.error,
                                           message: "Invalid rule database received from Moroz")

                case RuleDatabaseStatus.partial:
                    acceptRules = true

                    self.logger.logMessage(severity: LogMessageSeverity.error,
                                           message: "Moroz has sent one or more invalid rules")

                case RuleDatabaseStatus.valid:
                    acceptRules = true
                }

                if acceptRules {
                    self.ruleDatabase = newRuleDatabase
                }

            } else {
                self.logger.logMessage(severity: LogMessageSeverity.error,
                                       message: "No data received from the Moroz server")
            }
        })

        task.resume()
    }
}
