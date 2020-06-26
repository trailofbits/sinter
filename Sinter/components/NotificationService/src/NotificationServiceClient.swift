/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

fileprivate class NotificationClient: NotificationClientInterface {
    var connectionOpt: NSXPCConnection?
    var serviceOpt: NotificationServiceProtocol?

    private func getClient() -> NotificationServiceProtocol? {
        if connectionOpt == nil {
            connectionOpt = NSXPCConnection(machServiceName: "com.trailofbits.sinter.notification-server")

            connectionOpt!.remoteObjectInterface = NSXPCInterface(with: NotificationServiceProtocol.self)
            connectionOpt!.resume()
        }

        if serviceOpt == nil {
            serviceOpt = connectionOpt!.remoteObjectProxyWithErrorHandler { _ in
                self.connectionOpt!.invalidate()

                self.connectionOpt = nil
                self.serviceOpt = nil
            } as? NotificationServiceProtocol
        }

        return serviceOpt
    }

    public func showNotification(message: String) {
        if let service = getClient() {
            service.showNotification(message: message)

        } else {
            print("Notification server not ready. Message: \(message)")
        }
    }
}

public func createNotificationClient() -> NotificationClientInterface {
    NotificationClient()
}
