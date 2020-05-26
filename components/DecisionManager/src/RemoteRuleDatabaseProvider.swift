/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Logger
import Configuration

class RemoteRuleDatabaseProvider : RuleDatabaseProviderInterface {
    private let logger: LoggerInterface

    private var serverURL = String()
    private var machineIdentifier = String()

    init(logger: LoggerInterface) {
        self.logger = logger
    }

    func getRuleDatabase(configuration: ConfigurationInterface) -> RuleDatabase? {
        if let serverURL = configuration.stringValue(section: "RemoteDecisionManager",
                                                     key: "server_url") {

            self.serverURL = serverURL

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'server_url' key is missing from the RemoteDecisionManager section")
            
            return nil
        }

        if let machineIdentifier = configuration.stringValue(section: "RemoteDecisionManager",
                                                     key: "machine_identifier") {

            self.machineIdentifier = machineIdentifier

        } else {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'machine_identifier' key is missing from the RemoteDecisionManager section")
            
            return nil
        }

        return requestRuleDatabase()
    }

    private func requestRuleDatabase() -> RuleDatabase? {
        let requestAddress = serverURL +
                             "/v1/santa/ruledownload/" +
                             machineIdentifier

        let requestUrlOpt = URL(string: requestAddress)
        if requestUrlOpt == nil {
            self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                   message: "The following server URL is not valid: '\(requestAddress)'")

            return nil
        }

        var request = URLRequest(url: requestUrlOpt!)
        request.httpMethod = "POST"

        let session = URLSession.shared
        var ruleDatabase: RuleDatabase? = nil

        let dg = DispatchGroup()
        dg.enter()

        let task = session.dataTask(with: request,
                                    completionHandler: { dataOpt, _, errorOpt -> Void in

            if let error = errorOpt {
                let errorMessage = "Failed to contact the remote server: " + error.localizedDescription

                self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                       message: errorMessage)

                dg.leave()
                return
            }
            
            if dataOpt == nil {
                self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                       message: "The remote has not answered to the POST request")

                dg.leave()
                return
            }

            let newRuleDatabase = parseJSONRuleDatabase(jsonData: dataOpt!)

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
                ruleDatabase = newRuleDatabase
            }
                                        
            dg.leave()
        })

        task.resume()
        dg.wait()

        return ruleDatabase
    }
}
