#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
# 

#
# List valid codesign identities with
#   security find-identity -v -p codesigning
#

function(codesign target_name)
  if(NOT SINTER_CODESIGN_IDENTITY)
    message(WARNING "Skipping code signing because no identity was specified")
    return()
  endif()

  add_custom_command(
    TARGET "${target_name}" POST_BUILD
    COMMAND codesign --entitlements "${CMAKE_SOURCE_DIR}/plist/entitlements.plist" --force -s "${SINTER_CODESIGN_IDENTITY}" -v "$<TARGET_FILE:${target_name}>"
    COMMENT "Codesigning target ${target_name}..."
    VERBATIM
  )
endfunction()

