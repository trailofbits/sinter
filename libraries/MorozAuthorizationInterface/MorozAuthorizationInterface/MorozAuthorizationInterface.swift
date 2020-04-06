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
    private let machineIdentifier: String

    private var ruleDatabaseUpdateTimer = Timer()
    private var ruleDatabase = RuleDatabase()
    private let defaultAllow: Bool

    public init?(logger: ILogger, serverAddress: String, configUpdateInterval: TimeInterval, defaultAllow: Bool) {
        self.logger = logger
        self.serverAddress = serverAddress
        self.defaultAllow = defaultAllow

        // TODO: this should be a unique identifier that is hard to guess
        machineIdentifier = "Sinter"

        ruleDatabaseUpdateTimer = Timer.scheduledTimer(withTimeInterval: configUpdateInterval,
                                                       repeats: true) { _ in self.requestRuleDatabaseUpdate() }

        ruleDatabaseUpdateTimer.fire()
    }

    deinit {
        self.ruleDatabaseUpdateTimer.invalidate()
    }

    public func ruleForBinary(request: IAuthorizationInterfaceRequest, allow: inout Bool, cache: inout Bool) -> Bool {
        cache = false

        if request.isAppleSigned {
            allow = true

        } else if let rule = ruleDatabase.binaryRuleMap[request.cdhash] {
            allow = rule.policy == RulePolicy.whitelist

        } else if let rule = ruleDatabase.certificateRuleMap[request.signingId] {
            allow = rule.policy == RulePolicy.whitelist

        } else {
            allow = defaultAllow
        }

        if !allow {
            print("Denied", request.cdhash)
        }

        return true
    }

    private func requestRuleDatabaseUpdate() {
        logger.logMessage(severity: LogMessageSeverity.information,
                          message: "Updating rules...")

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
