cmake_minimum_required(VERSION 3.17.3)
project("Sinter")

set(SINTER_NOTARIZED_APPLICATION_BUNDLE_PATH "" CACHE PATH "The path to the Sinter.app application bundle")

function(sinterPackage)
  install(
    DIRECTORY
      "${SINTER_NOTARIZED_APPLICATION_BUNDLE_PATH}"

    USE_SOURCE_PERMISSIONS

    COMPONENT
      "ApplicationBundle"

    DESTINATION
      "/Applications"
  )

  install(
    PROGRAMS
      "${CMAKE_CURRENT_SOURCE_DIR}/resources/uninstall.sh"

    COMPONENT
      "ApplicationBundle"

    DESTINATION
      "/Library/Application Support/Sinter"
  )

  install(
    DIRECTORY
      "${CMAKE_CURRENT_SOURCE_DIR}/../../config/"

    COMPONENT
      "DefaultConfiguration"

    DESTINATION
      "/etc/sinter"

    FILES_MATCHING
      PATTERN "*.json"
  )
endfunction()

function(getSinterVersion output_variable bundle_path)
  execute_process(
    COMMAND defaults read "${bundle_path}/Contents/Info.plist" CFBundleShortVersionString
    RESULT_VARIABLE process_exit_code
    OUTPUT_VARIABLE sinter_version
  )

  if(NOT ${process_exit_code} EQUAL 0)
    message(FATAL_ERROR "Failed to determine the Sinter.app bundle version")
  endif()

  string(STRIP "${sinter_version}" sinter_version)
  set("${output_variable}" "${sinter_version}" PARENT_SCOPE)
endfunction()

function(setCPackPackageVersion sinter_version)
  string(REPLACE "." ";" "sinter_version_components" "${sinter_version}")

  list(GET sinter_version_components 0 "major_version")
  list(GET sinter_version_components 1 "minor_version")
  list(GET sinter_version_components 2 "patch_version")

  message(STATUS "Sinter version: ${major_version}.${minor_version}.${patch_version}")

  set(CPACK_PACKAGE_VERSION_MAJOR "${major_version}" PARENT_SCOPE)
  set(CPACK_PACKAGE_VERSION_MINOR "${minor_version}" PARENT_SCOPE)
  set(CPACK_PACKAGE_VERSION_PATCH "${patch_version}" PARENT_SCOPE)
endfunction()

set(CPACK_PACKAGE_VENDOR "trailofbits")
set(CPACK_PACKAGE_CONTACT "info@trailofbits.com")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://www.trailofbits.com")

getSinterVersion("SINTER_VERSION" "${SINTER_NOTARIZED_APPLICATION_BUNDLE_PATH}")
setCPackPackageVersion("${SINTER_VERSION}")

set(CPACK_PACKAGE_RELOCATABLE true)
set(CPACK_GENERATOR "productbuild")
set(CPACK_SET_DESTDIR true)

set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_COMPONENT_APPLICATIONBUNDLE_DESCRIPTION "A user-mode application authorization system for MacOS written in Swift")
set(CPACK_COMPONENT_DEFAULTCONFIGURATION_DESCRIPTION "The default configuration files for Sinter")

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_BINARY_DIR}/license.txt")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/resources/readme.txt")
set(CPACK_RESOURCE_FILE_WELCOME "${CMAKE_CURRENT_SOURCE_DIR}/resources/welcome.txt")

set(CPACK_COMPONENTS_ALL "ApplicationBundle;DefaultConfiguration")

if(NOT DEFINED ENV{SINTER_INSTALLER_CODESIGN_IDENTITY})
  message(FATAL_ERROR "The following environment variable is not defined: SINTER_INSTALLER_CODESIGN_IDENTITY")
endif()

set(CPACK_PRODUCTBUILD_IDENTITY_NAME "$ENV{SINTER_INSTALLER_CODESIGN_IDENTITY}")
set(CPACK_PKGBUILD_IDENTITY_NAME "$ENV{SINTER_INSTALLER_CODESIGN_IDENTITY}")

set(CPACK_PREFLIGHT_APPLICATIONBUNDLE_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/scripts/preflight.sh")
set(CPACK_POSTFLIGHT_APPLICATIONBUNDLE_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/scripts/postflight.sh")

# Generate the license file before we include CPack; we can't use the LICENSE file we have
# directly since CPack requires the file name to end with a known file extension
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E create_symlink "${CMAKE_CURRENT_SOURCE_DIR}/../../LICENSE" "${CMAKE_CURRENT_BINARY_DIR}/license.txt"
)

include(CPack)

sinterPackage()
