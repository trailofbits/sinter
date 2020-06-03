/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import XCTest
@testable import Logger

fileprivate typealias LoggedMessage = [String: String]

class LoggerTests: XCTestCase {
    private func validateLoggedMessage(message: String,
                                       expectedSeverity: LoggerMessageSeverity,
                                       expectedMessage: String) {
        var newlineCount = 0
        for c in message {
            if c == "\n" {
                newlineCount += 1
            }
        }
        
        XCTAssertEqual(newlineCount, 1)

        let lastCharacterOpt = message.last
        XCTAssertNotNil(lastCharacterOpt)

        XCTAssertEqual(lastCharacterOpt!, "\n")

        let dataOpt = message.data(using: .utf8)
        XCTAssertNotNil(dataOpt)

        var loggedMessage = LoggedMessage()

        do {
            loggedMessage = try JSONDecoder().decode(LoggedMessage.self,
                                                     from: dataOpt!)
        } catch {
        }
        
        XCTAssertFalse(loggedMessage.isEmpty)

        let timestampOpt = loggedMessage["timestamp"]
        XCTAssertNotNil(timestampOpt)

        let objectTypeOpt = loggedMessage["type"]
        XCTAssertNotNil(objectTypeOpt)

        let loggedSeverityOpt = loggedMessage["severity"]
        XCTAssertNotNil(loggedSeverityOpt)
        
        let loggedMessageOpt = loggedMessage["message"]
        XCTAssertNotNil(loggedMessageOpt)
        
        XCTAssertEqual(objectTypeOpt!, "message")
        XCTAssertEqual(loggedSeverityOpt!, "\(expectedSeverity)")
        XCTAssertEqual(loggedMessageOpt!, "\(expectedMessage)")
    }

    func testMessageGenerator() throws {
        let testMessage = "Test message"

        for severity in LoggerMessageSeverity.allCases {
            let message = FilesystemLogger.generateLogMessage(severity: severity,
                                                              message: testMessage)

            validateLoggedMessage(message: message,
                                  expectedSeverity: severity,
                                  expectedMessage: testMessage)
        }
    }

    func testFileWriter() throws {
        let context = FilesystemLoggerContext()

        let severity = LoggerMessageSeverity.information
        let message = "Test"

        var succeeded = FilesystemLogger.logMessage(context: context,
                                                    severity: severity,
                                                    message: message)

        XCTAssertFalse(succeeded)

        let logFilePath = NSTemporaryDirectory() + "/" + String(getpid())
        context.logFileURL = URL(fileURLWithPath: logFilePath)

        succeeded = FilesystemLogger.logMessage(context: context,
                                                severity: severity,
                                                message: message)

        XCTAssertTrue(succeeded)

        var loggedMessage = String()
        
        do {
            loggedMessage = try String(contentsOf: context.logFileURL)
        } catch {
        }
        
        XCTAssertFalse(loggedMessage.isEmpty)
        validateLoggedMessage(message: loggedMessage,
                              expectedSeverity: severity,
                              expectedMessage: message)
    }
}
