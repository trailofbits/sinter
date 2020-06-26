/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

import NotificationService

/*
 Quote from the 'terminal-notifier' project:

 It is currently packaged as an application bundle, because
 NSUserNotification does not work from a 'Foundation tool'.

 radar://11956694
 */

let notificationCenter: NotificationCenter

let notificationCenterExp = NotificationCenter.create()
switch notificationCenterExp {
case let .success(obj):
    notificationCenter = obj

case let .failure(error):
    print("Failed to create the NotificationCenter object: \(error)")
    exit(EXIT_FAILURE)
}

print("Starting the notification server")
let notificationServer = createNotificationServer(notificationService: notificationCenter)

notificationCenter.showNotification(message: "The Sinter notification server is running")

RunLoop.current.run()
dispatchMain()
