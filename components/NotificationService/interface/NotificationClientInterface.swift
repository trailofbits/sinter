/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public protocol NotificationClientInterface {
    func showNotification(message: String)

    func requestAuthorization(binaryPath: String,
                              hash: String,
                              allowExecution: inout Bool)
}
