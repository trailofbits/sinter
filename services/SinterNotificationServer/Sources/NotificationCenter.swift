/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Cocoa
import Foundation
import UserNotifications

import NotificationService

enum NotificationCenterError: Error {
    case userNotificationAccessDenied
}

class NotificationCenter: NotificationServiceProtocol {
    private let notificationCenter: UNUserNotificationCenter

    private init() throws {
        notificationCenter = UNUserNotificationCenter.current()

        let accessGrantedDg = DispatchGroup()
        accessGrantedDg.enter()

        var accessGranted = false
        notificationCenter.requestAuthorization(options: [.alert, .badge, .sound]) { granted, error in
            if granted {
                accessGranted = true

            } else {
                print("Access to UserNotifications has *NOT* been granted:", error!)
            }

            accessGrantedDg.leave()
        }

        accessGrantedDg.wait()
        if !accessGranted {
            throw NotificationCenterError.userNotificationAccessDenied
        }
    }

    static func create() -> Result<NotificationCenter, Error> {
        Result<NotificationCenter, Error> { try NotificationCenter() }
    }

    func showNotification(message: String) {
        let content = UNMutableNotificationContent()
        content.title = "Sinter"
        content.body = message
        content.sound = UNNotificationSound.default

        let request = UNNotificationRequest(identifier: UUID().uuidString,
                                            content: content,
                                            trigger: nil)

        notificationCenter.add(request)
    }

    func requestAuthorization(binaryPath: String,
                              hash: String,
                              reply: @escaping (_ allow: Bool, _ cache: Bool) -> Void) {
        DispatchQueue.main.sync {
            let alert = NSAlert()

            alert.messageText = "Sinter needs to allow an unknown program"
            alert.informativeText = "Path: \(binaryPath)\nHash: \(hash)"
            alert.alertStyle = .warning
            alert.addButton(withTitle: "Allow")
            alert.addButton(withTitle: "Deny")

            let allow = alert.runModal() == .alertFirstButtonReturn
            reply(allow, false)
        }
    }
}
