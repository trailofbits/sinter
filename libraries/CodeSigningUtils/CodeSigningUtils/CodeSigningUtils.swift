/*
 Copyright (c) 2019-present, Trail of Bits, Inc.
 All rights reserved.

 This source code is licensed in accordance with the terms specified in
 the LICENSE file found in the root directory of this source tree.
 */

import Foundation

public enum CodeSignatureStatus {
    case InternalError
    case Valid
    case IOError
    case Invalid
}

public func checkCodeSignature(path: String) -> CodeSignatureStatus {
    let fileUrl: URL? = URL(fileURLWithPath: path)
    if fileUrl == nil {
        return CodeSignatureStatus.IOError
    }

    let checkFlags: SecCSFlags? = SecCSFlags(rawValue: kSecCSCheckNestedCode)
    if checkFlags == nil {
        return CodeSignatureStatus.InternalError
    }

    var staticCodeObj: SecStaticCode?
    var err: OSStatus = SecStaticCodeCreateWithPath(fileUrl! as CFURL, [], &staticCodeObj)
    if err != OSStatus(noErr) || staticCodeObj == nil {
        return CodeSignatureStatus.IOError
    }

    let secRequirement: SecRequirement? = nil
    var secErr: Unmanaged<CFError>?
    err = SecStaticCodeCheckValidityWithErrors(staticCodeObj!,
                                               checkFlags!,
                                               secRequirement,
                                               &secErr)

    if secErr != nil {
        secErr?.release()
    }

    if err != errSecSuccess {
        return CodeSignatureStatus.Invalid
    }

    return CodeSignatureStatus.Valid
}
