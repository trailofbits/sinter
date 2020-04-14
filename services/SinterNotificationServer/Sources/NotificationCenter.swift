/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation
import UserNotifications

import NotificationService

private let execAuthRequestIdentifier = "EXEC_AUTH_REQUEST"
private let allowExecAuthRequestIdentifier = "ALLOW_ACTION"
private let denyExecAuthRequestIdentifier = "DENY_ACTION"

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

        let allowAction = UNNotificationAction(identifier: allowExecAuthRequestIdentifier,
                                               title: "Allow",
                                               options: UNNotificationActionOptions(rawValue: 0))

        let denyAction = UNNotificationAction(identifier: denyExecAuthRequestIdentifier,
                                              title: "Deny",
                                              options: UNNotificationActionOptions(rawValue: 0))

        let execAuthorizationRequestCategory = UNNotificationCategory(identifier: execAuthRequestIdentifier,
                                                                      actions: [allowAction, denyAction],
                                                                      intentIdentifiers: [],
                                                                      hiddenPreviewsBodyPlaceholder: "",
                                                                      options: .customDismissAction)

        notificationCenter.setNotificationCategories([execAuthorizationRequestCategory])

        requestAuthorization(binaryPath: "/Applications/CMake.app",
                             hash: "0e4df360b5763df4160bab1e686b510cb484f51d")
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

    func requestAuthorization(binaryPath: String, hash _: String) -> Bool {
        let content = UNMutableNotificationContent()
        content.title = "Sinter"
        content.body = "Select action for \(binaryPath)"
        content.sound = UNNotificationSound.default
        content.categoryIdentifier = execAuthRequestIdentifier

        let request = UNNotificationRequest(identifier: UUID().uuidString,
                                            content: content,
                                            trigger: nil)

        notificationCenter.add(request)

        return true
    }
}
