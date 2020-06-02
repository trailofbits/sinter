/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

if CommandLine.arguments.count != 2 {
    print("Usage:\n\tsignature-checker /path/to/application")
    exit(EXIT_FAILURE)
}

let path = CommandLine.arguments[1]

let url: URL? = URL(fileURLWithPath: path)
if url == nil {
    print("The following path is not valid: \(path)")
    exit(EXIT_FAILURE)
}

let checkFlags: SecCSFlags? = SecCSFlags(rawValue: kSecCSCheckNestedCode)
if checkFlags == nil {
    print("Failed to initialize the SecCSFlags object")
    exit(EXIT_FAILURE)
}

var staticCodeObj: SecStaticCode?
var err: OSStatus = SecStaticCodeCreateWithPath(url! as CFURL, [], &staticCodeObj)
if err != OSStatus(noErr) || staticCodeObj == nil {
    print("Failed to initialize the SecStaticCode object")
    exit(EXIT_FAILURE)
}

let requirement: SecRequirement? = nil
var error: Unmanaged<CFError>?
err = SecStaticCodeCheckValidityWithErrors(staticCodeObj!,
                                           checkFlags!,
                                           requirement,
                                           &error)

if error != nil {
    //print("SecStaticCodeCheckValidityWithErrors returned \(String(describing: error!))")
    error?.release()
}

if err != errSecSuccess {
    //print("SecStaticCodeCheckValidityWithErrors returned \(String(describing: err))")
    exit(EXIT_FAILURE)
}

exit(EXIT_SUCCESS)
