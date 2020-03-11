#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.4)

function(sinterLibrariesCodeSigningUtils)
  add_library(CodeSigningUtils
    src/CodeSigningUtils.swift
  )

  if(SINTER_ENABLE_TESTS)
    target_compile_options(CodeSigningUtils PRIVATE
      "-enable-testing"
    )
  endif()

  target_include_directories(CodeSigningUtils INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}"
  )

  addSinterTest(
    NAME
      "CodeSigningUtils"

    SOURCES
      "tests/TestCodeSigningUtils.swift"

    LIBRARIES
      CodeSigningUtils
  )
endfunction()

sinterLibrariesCodeSigningUtils()

