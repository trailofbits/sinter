#!/usr/bin/env bash

main() {
  if [[ $# != 1 ]] ; then
    printf "Usage:\n\tnotarize.sh /path/to/file\n\n"
    printf "The input file can either be an application bundle (.app) or an installer package (.pkg)\n"

    return 1
  fi

  local input_file="$1"

  if [[ ! -f "${input_file}" ]] && [[ ! -d "${input_file}" ]] ; then
    printf "The following input file does not exists or is not accessible: ${input_file}\n"
    return 1
  fi

  checkEnvironmentVariables || return 1

  local input_file_extension="${input_file: -4}"
  if [[ "${input_file_extension}" == ".pkg" ]] ; then
    printf "The input file appears to be a PKG installer\n"
    notarizeProduct "${input_file}" || return 1

  elif [[ "${input_file_extension}" == ".app" ]] ; then
    printf "The input file appears to be an application bundle\n"

    printf "Compressing the application bundle\n"

    archive_path="$(mktemp).zip"
    ditto -c -k --keepParent "${input_file}" "${archive_path}"
    if [[ $? -ne 0 ]] ; then
      printf "Failed to prepare the application archive\n"
      return 1
    fi

    notarizeProduct "${archive_path}" || return 1

  else
    printf "The input file was not recognized. Only application bundles and PKG installers are supported\n"
    return 1
  fi

  printf "Running the stapling procedure...\n"
  xcrun stapler staple "${input_file}"
  if [[ $? != 0 ]] ; then
    printf "The stapling procedure has failed\n"
    return 1
  fi
  
  return 0
}

checkEnvironmentVariables() {
  if [[ -z "${SINTER_APPLE_ACCOUNT_ID}" ]] ; then
    printf "The following environment variable is not defined: SINTER_APPLE_ACCOUNT_ID\n"
    return 1
  fi

  if [[ -z "${SINTER_APPLE_ACCOUNT_PASSWORD}" ]] ; then
    printf "The following environment variable is not defined: SINTER_APPLE_ACCOUNT_PASSWORD\n"
    return 1
  fi

  if [[ -z "${SINTER_APPLE_ACCOUNT_TEAM_ID}" ]] ; then
    printf "The following environment variable is not defined: SINTER_APPLE_ACCOUNT_TEAM_ID\n"
    return 1
  fi

  return 0
}

notarizeProduct() {
  if [[ $# != 1 ]] ; then
    printf "Usage:\n\tnotarizeProduct /path/to/product.{zip|pkg}\n"
    return 1
  fi

  local archive_path="$1"

  local notarization_log="$(mktemp)"
  printf "Initiating the notarization process (${notarization_log})\n"
  xcrun altool --notarize-app -u "${SINTER_APPLE_ACCOUNT_ID}" -p "${SINTER_APPLE_ACCOUNT_PASSWORD}" -f "${archive_path}" --primary-bundle-id com.trailofbits.sinter --asc-provider "${SINTER_APPLE_ACCOUNT_TEAM_ID}" > "${notarization_log}" 2>&1
  if [[ $? != 0 ]] ; then
    dumpLogFile "${notarization_log}"
    return 1
  fi

  local request_uuid="$(grep RequestUUID ${notarization_log} | awk '{ print $(NF) }')"
  printf "Request UUID: ${request_uuid}\n"

  local notarization_info_log="$(mktemp)"

  while true ; do
    sleep 2

    xcrun altool --notarization-info "${request_uuid}" -u "${SINTER_APPLE_ACCOUNT_ID}" -p "${SINTER_APPLE_ACCOUNT_PASSWORD}" > "${notarization_info_log}" 2>&1
    if [[ $? != 0 ]] ; then
      dumpLogFile "${notarization_info_log}"
      return 1
    fi

    grep 'Status: in progress' "${notarization_info_log}" > /dev/null 2>&1
    if [[ $? == 1 ]] ; then
      break
    fi
  done

  grep 'Status Message: Package Approved' "${notarization_info_log}" > /dev/null 2>&1
  if [[ $? == 1 ]] ; then
    printf "The package was not approved\n"
    dumpLogFile "${notarization_info_log}"
    return 1
  fi

  printf "The package was approved\n"
  dumpLogFile "${notarization_info_log}"

  return 0
}

dumpLogFile() {
  if [[ $# != 1 ]] ; then
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
