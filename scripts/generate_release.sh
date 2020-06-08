#!/usr/bin/env bash

main() {
  checkEnvironmentVariables || return 1

  if [[ ! -d "Sinter.xcodeproj" ]] ; then
    printf "The generate_release.sh script must be run from the repository root\n"
    return 1
  fi

  buildApplication || return 1
  notarizeApplicationBundle || return 1
  buildInstaller || return 1

  return 0
}

checkEnvironmentVariables() {
  if [[ "${APPLE_ACCOUNT_ID}" == "" ]] ; then
    printf "The environment variable containing the Apple account ID is not defined: APPLE_ACCOUNT_ID\n"
    return 1
  fi

  if [[ "${APPLE_ACCOUNT_PASSWORD}" == "" ]] ; then
    printf "The environment variable containing the Apple account password is not defined: APPLE_ACCOUNT_PASSWORD\n"
    return 1
  fi

  if [[ "${APPLE_ACCOUNT_APPLICATION_TEAM_SHORT}" == "" ]] ; then
    printf "The environment variable containing the team identifier is not defined: APPLE_ACCOUNT_APPLICATION_TEAM_SHORT\n"
    return 1
  fi

  if [[ "${APPLE_ACCOUNT_INSTALLER_TEAM_FULL}" == "" ]] ; then
    printf "The environment variable containing the team identifier is not defined: APPLE_ACCOUNT_INSTALLER_TEAM_FULL\n"
    return 1
  fi

  return 0
}

buildApplication() {
  local build_log="$(mktemp)"

  printf "Cleaning the project\n"
  xcodebuild -configuration Release -scheme Sinter clean > "${build_log}" 2>&1
  if [[ $? -ne 0 ]] ; then
    dumpLogFile "${build_log}"
    return 1
  fi

  printf "Building the project\n"
  xcodebuild -configuration Release -scheme Sinter > "${build_log}" 2>&1
  if [[ $? -ne 0 ]] ; then
    dumpLogFile "${build_log}"
    return 1
  fi

  local codesign_invocation=$(grep "/usr/bin/codesign" "${build_log}" | grep "Sinter.app" | tail -n1)
  local app_bundle_path="$(echo ${codesign_invocation} | awk '{ print $(NF) }')"

  if [[ ! -d "${app_bundle_path}" ]] ; then
    printf "The Sinter.app bundle could not be found\n"
    return 1
  fi

  if [[ -d "packaging/macOS-x64/application/Sinter.app" ]] ; then
    rm -rf "packaging/macOS-x64/application/Sinter.app"
    if [[ $? -ne 0 ]] ; then
      printf "Failed to delete the Sinter bundle from the packaging/macOS-x64/application folder\n"
      return 1
    fi
  fi

  mv "${app_bundle_path}" "packaging/macOS-x64/application/Sinter.app"
  if [[ $? -ne 0 ]] ; then
    printf "Failed to move the generated Sinter.app bundle\n"
    return 1
  fi

  return 0
}

notarizeApplicationBundle() {
  local temporary_folder="$(mktemp -d)"
  local archive_path="${temporary_folder}/Sinter.app.zip"

  printf "Compressing the application bundle\n"
  ditto -c -k --keepParent "packaging/macOS-x64/application/Sinter.app" "${archive_path}"
  if [[ $? -ne 0 ]] ; then
    printf "Failed to prepare the application archive\n"
    return 1
  fi

  local notarization_log="$(mktemp)"
  printf "Initiating the notarization process (${notarization_log})\n"
  xcrun altool --notarize-app -u "${APPLE_ACCOUNT_ID}" -p "${APPLE_ACCOUNT_PASSWORD}" -f "${archive_path}" --primary-bundle-id com.trailofbits.sinter --asc-provider "${APPLE_ACCOUNT_APPLICATION_TEAM_SHORT}" > "${notarization_log}" 2>&1
  if [[ $? -ne 0 ]] ; then
    dumpLogFile "${notarization_log}"
    return 1
  fi

  local request_uuid="$(grep RequestUUID ${notarization_log} | awk '{ print $(NF) }')"
  printf "Request UUID: ${request_uuid}\n"

  local notarization_info_log="$(mktemp)"

  while true ; do
    sleep 2

    xcrun altool --notarization-info "${request_uuid}" -u "${APPLE_ACCOUNT_ID}" -p "${APPLE_ACCOUNT_PASSWORD}" > "${notarization_info_log}" 2>&1
    if [[ $? -ne 0 ]] ; then
      dumpLogFile "${notarization_info_log}"
      return 1
    fi

    grep 'Status: in progress' "${notarization_info_log}" > /dev/null 2>&1
    if [[ $? -eq 1 ]] ; then
      break
    fi
  done

  grep 'Status Message: Package Approved' "${notarization_info_log}" > /dev/null 2>&1
  if [[ $? -eq 1 ]] ; then
    printf "The package was not approved\n"
    dumpLogFile "${notarization_info_log}"
    return 1
  fi

  printf "The package was approved\n"
  dumpLogFile "${notarization_info_log}"

  printf "Running the stapling procedure\n"
  local stapler_log="$(mktemp)"
  xcrun stapler staple "packaging/macOS-x64/application/Sinter.app" > "${stapler_log}" 2>&1
  if [[ $? -ne 0 ]] ; then
    printf "The stapling procedure has failed\n"
    dumpLogFile "${stapler_log}"
    return 1
  fi

  return 0
}

buildInstaller() {
  printf "Downloading the git tags from the repository\n"
  git fetch --tags > /dev/null 2>&1
  if [[ $? -ne 0 ]] ; then
    printf "Failed to fetch the git tags from the repository\n"
    return 1
  fi

  local sinter_version=$(git describe --tags --abbrev=0)
  if [[ $? -ne 0 ]] ; then
    printf "Failed to determine the version from the git tag\n"
    return 1
  fi

  printf "Version: ${sinter_version}\n"

  local packager_log="$(mktemp)"
  printf "Generating the PKG installer (${packager_log})\n"

  ( cd "packaging/macOS-x64" && ./build-macos-x64.sh "${sinter_version}" ) > "${packager_log}" 2>&1
  if [[ $? -ne 0 ]] ; then
    printf "Failed to create the PKG installer\n"
    dumpLogFile "${packager_log}"
    return 1
  fi

  printf "The package has been created\n"
  dumpLogFile "${packager_log}"

  printf "Package path: $(pwd)/packaging/macOS-x64/target/pkg-signed/Sinter-macos-installer-x64-0.1.1.pkg\n"
  return 0
}

dumpLogFile() {
  if [[ $# -ne 1 ]] ; then
    printf "Usage:\n\tdumpLogFile /path/to/log/file\n"
    return
  fi

  local log_file_path="$1"

  if [[ ! -f "${log_file_path}" ]] ; then
    printf "The following log file was not found: ${log_file_path}\n"
    return
  fi

  printf "Log file: ${log_file_path}\n==========\n"
  cat "${log_file_path}"
}

main $@
exit $?
