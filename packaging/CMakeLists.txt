project("SinterPackage")
cmake_minimum_required(VERSION 3.17.3)

function(sinterPackage)
  checkEnvironmentVariables()

  getSinterVersion("sinter_version" "${CMAKE_CURRENT_SOURCE_DIR}/../Sinter/application/Info.plist")

  # Create the build folder for the application bundle
  set(app_build_folder "${CMAKE_CURRENT_BINARY_DIR}/application")

  add_custom_command(
    OUTPUT "${app_build_folder}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${app_build_folder}"
    COMMENT "Creating the application build folder..."
  )

  add_custom_target(app_build_folder_creator
    DEPENDS "${app_build_folder}"
  )

  # Build the Sinter.app application
  set(app_path "${app_build_folder}/Release/Sinter.app")
  set(xcode_project_root "${CMAKE_CURRENT_SOURCE_DIR}/..")

  add_custom_command(
    OUTPUT "${app_path}"
    COMMAND "${CMAKE_COMMAND}" -E rm -rf "${app_build_folder}/*"
    COMMAND xcodebuild -configuration Release -scheme Sinter SYMROOT=${app_build_folder}
    MAIN_DEPENDENCY "${xcode_project_root}/Sinter.xcodeproj"
    WORKING_DIRECTORY "${xcode_project_root}"
    COMMENT "Building Sinter..."
    VERBATIM
  )

  add_custom_target(app_builder
    DEPENDS "${app_path}"
  )
  
  add_dependencies(app_builder
    app_build_folder_creator
  )

  # Notarize the app bundle
  set(notarized_app_path "${CMAKE_CURRENT_BINARY_DIR}/Sinter.app")

  add_custom_command(
    OUTPUT "${notarized_app_path}"
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/notarize.sh" "${app_path}"
    COMMAND rsync -avx "${app_path}" "${CMAKE_CURRENT_BINARY_DIR}"
    MAIN_DEPENDENCY "${app_path}"
    COMMENT "Notarizing the application bundle..."
    VERBATIM
  )

  add_custom_target(notarized_app_builder
    DEPENDS "${notarized_app_path}"
  )

  add_dependencies(notarized_app_builder
    app_builder
  )

  # Create the builder folder for the PKG installer
  set(package_build_folder_path "${CMAKE_CURRENT_BINARY_DIR}/pkg")

  add_custom_command(
    OUTPUT "${package_build_folder_path}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/pkg"
    COMMENT "Creating the PKG build folder..."
    VERBATIM
  )

  add_custom_target(pkg_build_folder_builder
    DEPENDS "${package_build_folder_path}"
  )

  # Create the PKG installer
  set(package_name "Sinter-${sinter_version}-Darwin.pkg")
  set(package_path "${CMAKE_CURRENT_BINARY_DIR}/pkg/${package_name}")

  add_custom_command(
    OUTPUT "${package_path}"
    COMMAND "${CMAKE_COMMAND}" -DSINTER_NOTARIZED_APPLICATION_BUNDLE_PATH:PATH=${notarized_app_path} "${CMAKE_CURRENT_SOURCE_DIR}/pkg"
    COMMAND "${CMAKE_COMMAND}" --build . --target package
    MAIN_DEPENDENCY "${notarized_app_path}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/pkg"
    COMMENT "Building the PKG installer..."
    VERBATIM
  )

  add_custom_target(pkg_installer_builder
    DEPENDS "${package_path}"
  )

  add_dependencies(pkg_installer_builder
    pkg_build_folder_builder
    notarized_app_builder
  )

  # Notarize the PKG installer
  set(notarized_pkg_path "${CMAKE_CURRENT_BINARY_DIR}/${package_name}")

  add_custom_command(
    OUTPUT "${notarized_pkg_path}"
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/notarize.sh" "${package_path}"
    COMMAND "${CMAKE_COMMAND}" -E copy "${package_path}" "${notarized_pkg_path}"
    MAIN_DEPENDENCY "${package_path}"
    COMMENT "Notarizing the PKG installer..."
    VERBATIM
  )

  add_custom_target(package
    DEPENDS "${notarized_pkg_path}"
  )

  add_dependencies(package
    pkg_installer_builder
  )
endfunction()

# All the codesign settings are passed using environment variables so we get them directly
# from the CI secrets
function(checkEnvironmentVariables)
  set(terminate false)

  if(NOT DEFINED ENV{SINTER_INSTALLER_CODESIGN_IDENTITY})
    message(STATUS "The following environment variable is not defined: SINTER_INSTALLER_CODESIGN_IDENTITY")
    set(terminate true)
  endif()

  if(NOT DEFINED ENV{SINTER_APPLE_ACCOUNT_ID})
    message(STATUS "The following environment variable is not defined: SINTER_APPLE_ACCOUNT_ID")
    set(terminate true)
  endif()

  if(NOT DEFINED ENV{SINTER_APPLE_ACCOUNT_PASSWORD})
    message(STATUS "The following environment variable is not defined: SINTER_APPLE_ACCOUNT_PASSWORD")
    set(terminate true)
  endif()

  if(NOT DEFINED ENV{SINTER_APPLE_ACCOUNT_TEAM_ID})
    message(STATUS "The following environment variable is not defined: SINTER_APPLE_ACCOUNT_TEAM_ID")
    set(terminate true)
  endif()

  if(terminate)
    message(FATAL_ERROR "Terminating due to missing environment variables")
  endif()
endfunction()

# We need to know the package version before we actually build the
# application. This is unfortunate, but we need it so that we can setup
# the custom commands correctly
function(getSinterVersion output_variable plist_path)
  # Force an update of the version tag inside the plist file of the application bundle
  execute_process(
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/set_sinter_app_version.sh"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
  )

  # Now read the version from the app properties
  execute_process(
    COMMAND defaults read "${plist_path}" CFBundleShortVersionString
    RESULT_VARIABLE process_exit_code
    OUTPUT_VARIABLE sinter_version
  )

  if(NOT ${process_exit_code} EQUAL 0)
    message(FATAL_ERROR "Failed to determine the Sinter.app bundle version")
  endif()

  string(STRIP "${sinter_version}" sinter_version)
  set("${output_variable}" "${sinter_version}" PARENT_SCOPE)
endfunction()

sinterPackage()
