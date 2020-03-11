/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

@testable
import CodeSigningUtils

import Foundation

print("Attempting to generate an IOError error")
var status = checkCodeSignature(path: "/dummy_file")
if (status != CodeSignatureStatus.IOError) {
  print("Expected: IOError")
  exit(1)
}

print("Attempting to validate correct signature")
status = checkCodeSignature(path: "/bin/zsh")
if (status != CodeSignatureStatus.Valid) {
  print("Expected: Valid")
  exit(1)
}

print("Attempting to generate an Invalid error")
status = checkCodeSignature(path: "/etc/hosts")
if (status != CodeSignatureStatus.Invalid) {
  print("Expected: Invalid")
  exit(1)
}

exit(0)

