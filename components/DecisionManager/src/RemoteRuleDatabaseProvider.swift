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
    private let dispatchQueue = DispatchQueue(label: "com.trailofbits.sinter.remote-rule-database-provider")

    private var serverURL = String()
    private var machineIdentifier = String()
    private var database = RuleDatabase()

    init(logger: LoggerInterface) {
        self.logger = logger
    }

    func configure(configuration: ConfigurationInterface) {
        
        let serverURLOpt = configuration.stringValue(section: "RemoteDecisionManager",
                                                     key: "server_url")
        
        let machineIdentifierOpt = configuration.stringValue(section: "RemoteDecisionManager",
                                                             key: "machine_identifier")

        if serverURLOpt == nil {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'server_url' key is missing from the RemoteDecisionManager section")
            
            return
        }

        if machineIdentifierOpt == nil {
            logger.logMessage(severity: LoggerMessageSeverity.error,
                              message: "The 'machine_identifier' key is missing from the RemoteDecisionManager section")
            
            return
        }
        
        dispatchQueue.sync {
            serverURL = serverURLOpt!
            machineIdentifier = machineIdentifierOpt!
            
            requestRuleDatabaseUpdate()
        }
    }

    func ruleDatabase() -> RuleDatabase {
        var database = RuleDatabase()

        dispatchQueue.sync {
            database = self.database
        }

        return database
    }
    
    func requestRuleDatabaseUpdate() {
        let requestAddress = serverURL +
                             "/v1/santa/ruledownload/" +
                             machineIdentifier

        let requestUrlOpt = URL(string: requestAddress)
        if requestUrlOpt == nil {
            self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                   message: "The following server URL is not valid: '\(requestAddress)'")

            return
        }

        var request = URLRequest(url: requestUrlOpt!)
        request.httpMethod = "POST"

        let session = URLSession.shared
        let task = session.dataTask(with: request,
                                    completionHandler: { dataOpt, _, errorOpt -> Void in

            if let error = errorOpt {
                let errorMessage = "Failed to contact the remote server: " + error.localizedDescription

                self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                       message: errorMessage)

                return
            }
            
            if dataOpt == nil {
                self.logger.logMessage(severity: LoggerMessageSeverity.error,
                                       message: "The remote has not answered to the POST request")
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
                self.dispatchQueue.sync {
                    self.database = newRuleDatabase
                }
            }
        })

        task.resume()
    }
}
