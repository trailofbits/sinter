/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

private class NotificationClient: NotificationClientInterface {
    var connectionOpt: NSXPCConnection?
    var serviceOpt: NotificationServiceProtocol?

    private func getClient() -> NotificationServiceProtocol? {
        if connectionOpt == nil {
            connectionOpt = NSXPCConnection(machServiceName: "com.trailofbits.SinterNotificationServer")

            connectionOpt!.remoteObjectInterface = NSXPCInterface(with: NotificationServiceProtocol.self)
            connectionOpt!.resume()
        }

        if serviceOpt == nil {
            serviceOpt = connectionOpt!.synchronousRemoteObjectProxyWithErrorHandler { _ in
                self.connectionOpt!.invalidate()

                self.connectionOpt = nil
                self.serviceOpt = nil
            } as? NotificationServiceProtocol
        }

        return serviceOpt
    }

    init() {}

    public func showNotification(message: String) {
        if let service = getClient() {
            service.showNotification(message: message)

        } else {
            print("Notification server not ready. Message: \(message)")
        }
    }

    public func requestAuthorization(binaryPath: String,
                                     hash: String,
                                     allowExecution: inout Bool) {
        if let service = getClient() {
            let dg = DispatchGroup()
            dg.enter()

            var response = false

            service.requestAuthorization(binaryPath: binaryPath,
                                         hash: hash,
                                         reply: { (allowExecution: Bool) in
                                             response = allowExecution
                                             dg.leave()
            })

            if dg.wait(timeout: DispatchTime(uptimeNanoseconds: 1_000_000_000)) != DispatchTimeoutResult.success {
                response = false
            }

            allowExecution = response

        } else {
            print("Notification server not ready. Automatically denying \(binaryPath)/\(hash)")
            allowExecution = false
        }
    }
}

public func createNotificationClient() -> NotificationClientInterface {
    NotificationClient()
}
