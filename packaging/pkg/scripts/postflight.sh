#!/usr/bin/env bash

SINTER_DAEMON_NAME="Sinter.app/Contents/Library/SystemExtensions/com.trailofbits.sinter.daemon.systemextension"
NOTIFICATION_SERVER_NAME="Sinter.app/Contents/XPCServices/notification-server.app"

AUTHORIZATION_DAEMON_PLIST="/Library/LaunchDaemons/com.trailofbits.sinter.plist"
NOTIFICATION_SERVER_PLIST="/Library/LaunchAgents/com.trailofbits.sinter.notification-server.plist"

SINTER_INSTALLER_LOG="/tmp/sinter_installer.log"

main() {
  chown -R root:wheel /Applications/Sinter.app
  if [[ $? -ne 0 ]] ; then
    echo "Failed to set the Sinter.app owner to root:wheel" >> "${SINTER_INSTALLER_LOG}" 2>&1
    return 1
  fi

  pgrep "${SINTER_DAEMON_NAME}" > /dev/null 2>&1
  if [[ $? -eq 0 ]] ; then
    echo "The authorization daemon appears to be still running" >> "${SINTER_INSTALLER_LOG}" 2>&1
    exit 1
  fi

  /Applications/Sinter.app/Contents/MacOS/Sinter --install-notification-server >> "${SINTER_INSTALLER_LOG}" 2>&1
  if [[ $? -ne 0 ]] ; then
    echo "Failed to install the notification server" > "${SINTER_INSTALLER_LOG}"
    return 1
  fi

  local interactive_user="$(/usr/bin/stat -f '%u' /dev/console)"

  if [[ "${interactive_user}" != "" ]]; then
    echo "Starting the notification server"

    launchctl asuser "${interactive_user}" /Applications/Sinter.app/Contents/MacOS/Sinter --install-notification-server >> "${SINTER_INSTALLER_LOG}" 2>&1
    if [[ $? -ne 0 ]] ; then
      echo "Failed to start the notification server" > "${SINTER_INSTALLER_LOG}"
    fi

    sleep 1
  fi

  /Applications/Sinter.app/Contents/MacOS/Sinter --install-daemon >> "${SINTER_INSTALLER_LOG}" 2>&1
  if [[ $? -ne 0 ]] ; then
    echo "Failed to install the authorization daemon" > "${SINTER_INSTALLER_LOG}"
    return 1
  fi

  return 0
}

main $@
exit $?
