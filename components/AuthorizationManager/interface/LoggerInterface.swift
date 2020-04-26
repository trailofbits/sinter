/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public enum LoggerError: Error {
    case unknownError
}

public enum LoggerMessageSeverity {
    case debug
    case information
    case warning
    case error
}

public protocol LoggerInterface {
    func logMessage(severity: LoggerMessageSeverity, message: String)
}
