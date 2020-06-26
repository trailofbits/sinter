#!/usr/bin/env bash

SINTER_INSTALLER_LOG="/tmp/sinter_installer.log"
SINTER_UNINSTALLER="/Library/Application Support/Sinter/uninstall.sh"
SINTER_DAEMON_NAME="Sinter.app/Contents/Library/SystemExtensions/com.trailofbits.sinter.daemon.systemextension"

echo "$(date) - Running the pre-flight script" >> "${SINTER_INSTALLER_LOG}" 2>&1

if [[ -f "${SINTER_UNINSTALLER}" ]] ; then
  "${SINTER_UNINSTALLER}" >> "${SINTER_INSTALLER_LOG}" 2>&1
  exit $?

else
  echo "The uninstaller was not found. Making sure that Sinter is not running" >> "${SINTER_INSTALLER_LOG}" 2>&1
  launchctl stop "com.trailofbits.sinter" >> "${SINTER_INSTALLER_LOG}" 2>&1

  sleep 2

  pgrep "${SINTER_DAEMON_NAME}" > /dev/null 2>&1
  if [[ $? -eq 0 ]] ; then
    echo "The authorization daemon appears to be still running" >> "${SINTER_INSTALLER_LOG}" 2>&1
    exit 1
  fi

  exit 0
fi
