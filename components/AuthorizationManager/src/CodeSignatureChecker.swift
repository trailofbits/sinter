/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public enum CodeSignatureStatus {
    case internalError
    case valid
    case ioError
    case invalid
}

func checkCodeSignature(path: String) -> CodeSignatureStatus {
    let url: URL? = URL(fileURLWithPath: path)
    if url == nil {
        return CodeSignatureStatus.ioError
    }

    let checkFlags: SecCSFlags? = SecCSFlags(rawValue: kSecCSCheckNestedCode)
    if checkFlags == nil {
        return CodeSignatureStatus.internalError
    }

    var staticCodeObj: SecStaticCode?
    var err: OSStatus = SecStaticCodeCreateWithPath(url! as CFURL, [], &staticCodeObj)
    if err != OSStatus(noErr) || staticCodeObj == nil {
        return CodeSignatureStatus.ioError
    }

    let requirement: SecRequirement? = nil
    var error: Unmanaged<CFError>?
    err = SecStaticCodeCheckValidityWithErrors(staticCodeObj!,
                                               checkFlags!,
                                               requirement,
                                               &error)

    if error != nil {
        error?.release()
    }

    if err != errSecSuccess {
        return CodeSignatureStatus.invalid
    }

    return CodeSignatureStatus.valid
}
