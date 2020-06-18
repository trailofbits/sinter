/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import XCTest

@testable import AuthorizationManager

func testAllowedApplicationDirectories() {
    var applicationDirectorySettings = ApplicationDirectorySettings()
    applicationDirectorySettings.allowedApplicationDirectories.append("/Applications")
    applicationDirectorySettings.allowedApplicationDirectories.append("/usr/bin")

    applicationDirectorySettings.allowMisplacedApplications = true

    var isMisplaced = false
    var allowed = AuthorizationManager.isApplicationPathAllowed(applicationDirectorySettings: applicationDirectorySettings,
                                                                binaryPath: "/Applications/CMake.app",
                                                                isMisplaced: &isMisplaced)

    XCTAssertFalse(isMisplaced)
    XCTAssertTrue(allowed)

    allowed = AuthorizationManager.isApplicationPathAllowed(applicationDirectorySettings: applicationDirectorySettings,
                                                            binaryPath: "/bin/test",
                                                            isMisplaced: &isMisplaced)

    XCTAssertTrue(isMisplaced)
    XCTAssertTrue(allowed)

    applicationDirectorySettings.allowMisplacedApplications = false

    allowed = AuthorizationManager.isApplicationPathAllowed(applicationDirectorySettings: applicationDirectorySettings,
                                                            binaryPath: "/bin/test",
                                                            isMisplaced: &isMisplaced)

    XCTAssertTrue(isMisplaced)
    XCTAssertFalse(allowed)

    allowed = AuthorizationManager.isApplicationPathAllowed(applicationDirectorySettings: applicationDirectorySettings,
                                                            binaryPath: "/Applications/iTerm.app",
                                                            isMisplaced: &isMisplaced)

    XCTAssertFalse(isMisplaced)
    XCTAssertTrue(allowed)

    allowed = AuthorizationManager.isApplicationPathAllowed(applicationDirectorySettings: applicationDirectorySettings,
                                                            binaryPath: "/Applicationstest",
                                                            isMisplaced: &isMisplaced)

    XCTAssertTrue(isMisplaced)
    XCTAssertFalse(allowed)
}
