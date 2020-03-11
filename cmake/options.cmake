#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.16.5)

set(SINTER_CODESIGN_IDENTITY "" CACHE STRING "Codesign identity")
option(SINTER_ENABLE_TESTS "Set to true to enable tests" true)

