/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

private class NotificationServer: NotificationServerInterface {
    private let listener = NSXPCListener(machServiceName: "com.trailofbits.SinterNotificationServer")
    private let listenerDelegate: NotificationServerListenerDelegate

    init(notificationService: NotificationServiceProtocol) {
        listenerDelegate = NotificationServerListenerDelegate(notificationService: notificationService)

        listener.delegate = listenerDelegate
        listener.resume()
    }
}

private class NotificationServerListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let notificationService: NotificationServiceProtocol

    init(notificationService: NotificationServiceProtocol) {
        self.notificationService = notificationService
    }

    func listener(_: NSXPCListener,
                  shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: NotificationServiceProtocol.self)
        newConnection.exportedObject = notificationService
        newConnection.resume()

        return true
    }
}

public func createNotificationServer(notificationService: NotificationServiceProtocol) -> NotificationServerInterface {
    NotificationServer(notificationService: notificationService)
}
