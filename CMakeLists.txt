#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.5)
project("sinter" LANGUAGES Swift)

include("cmake/options.cmake")
include("cmake/codesign.cmake")
include("cmake/testing.cmake")

if(SINTER_ENABLE_TESTS)
  enable_testing()
endif()

function(sinterMain)
  add_subdirectory("libraries")

  add_executable("sinter"
    src/main.swift
    src/EndpointSecurityMessage.swift
    src/EndpointSecurity.swift
    src/AuthorizationManager.swift
    src/SignatureChecker.swift
  )

  target_link_libraries("sinter" PRIVATE
    thirdparty_endpointsecurity
    CodeSigningUtils
  )

  codesign("${PROJECT_NAME}")
endfunction()

sinterMain()

