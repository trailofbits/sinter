/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

import Foundation

enum CodeSignatureStatus {
  case InternalError
  case Valid
  case IOError
  case Invalid
}

func checkCodeSignature(path: String) -> CodeSignatureStatus {
  let file_url: URL? = URL(fileURLWithPath: path)
  if (file_url == nil) {
    return CodeSignatureStatus.IOError
  }

  let check_flags: SecCSFlags? = SecCSFlags.init(rawValue: kSecCSCheckNestedCode)
  if (check_flags == nil) {
    return CodeSignatureStatus.InternalError
  }

  var static_code_obj: SecStaticCode? = nil
  var err: OSStatus = SecStaticCodeCreateWithPath(file_url! as CFURL, [], &static_code_obj)
  if (err != OSStatus(noErr) || static_code_obj == nil) {
    return CodeSignatureStatus.IOError
  }

  let sec_requirement: SecRequirement? = nil
  var sec_err: Unmanaged<CFError>?
  err = SecStaticCodeCheckValidityWithErrors(static_code_obj!,
                                             check_flags!,
                                             sec_requirement,
                                             &sec_err)

  if (sec_err != nil) {
    sec_err?.release()
  }

  if (err != errSecSuccess) {
    return CodeSignatureStatus.Invalid
  }

  return CodeSignatureStatus.Valid
}
