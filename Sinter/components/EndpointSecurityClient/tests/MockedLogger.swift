/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Logger
import Configuration

fileprivate final class MockedLogger : LoggerInterface {
    func setConfiguration(configuration: ConfigurationInterface) { }
    func logMessage(severity: LoggerMessageSeverity, message: String) { }
}

func createMockedLogger() -> LoggerInterface {
    return MockedLogger()
}
