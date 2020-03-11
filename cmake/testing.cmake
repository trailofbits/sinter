#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.5)

function(addSinterTest)
  cmake_parse_arguments(
    PARSE_ARGV 0
    "ARGS"
    "CODESIGN_REQUIRED"
    "NAME"
    "SOURCES;LIBRARIES"
  )

  if("${ARGS_NAME}" STREQUAL "")
    message(FATAL_ERROR "Invalid test name specified")
  endif()

  if("${ARGS_SOURCES}" STREQUAL "")
    message(FATAL_ERROR "No source files specified for the test")
  endif()

  if(NOT SINTER_ENABLE_TESTS)
    return()
  endif()

  set(target_name "sinter_test_${ARGS_NAME}")
  add_executable("${target_name}"
    ${ARGS_SOURCES}
  )

  codesign("${target_name}")

  if(NOT "${ARGS_LIBRARIES}" STREQUAL "")
    target_link_libraries("${target_name}" PRIVATE ${ARGS_LIBRARIES})
  endif()

  if(ARGS_CODESIGN_REQUIRED AND "${SINTER_CODESIGN_IDENTITY}" STREQUAL "")
    message(WARNING "Test named ${ARGS_NAME} has been disabled because it requires codesigning but not identity has been set")
    return()
  endif()

  add_test(
    NAME "${target_name}_runner"
    COMMAND "$<TARGET_FILE:${target_name}>"
  )
endfunction()

