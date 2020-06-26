#!/usr/bin/env bash

SINTER_DAEMON_NAME="Sinter.app/Contents/Library/SystemExtensions/com.trailofbits.sinter.daemon.systemextension"
NOTIFICATION_SERVER_NAME="Sinter.app/Contents/XPCServices/notification-server.app"

AUTHORIZATION_DAEMON_PLIST="/Library/LaunchDaemons/com.trailofbits.sinter.plist"
NOTIFICATION_SERVER_PLIST="/Library/LaunchAgents/com.trailofbits.sinter.notification-server.plist"

main() {
  echo "Running the Sinter uninstaller"

  pgrep "${SINTER_DAEMON_NAME}" > /dev/null 2>&1
  if [[ $? -eq 0 ]] ; then
    echo "Stopping the authorization daemon"

    launchctl stop "com.trailofbits.sinter"
    if [[ $? -ne 0 ]] ; then
      echo "Failed to stop the authorization daemon"
      return 1
    fi
    
    sleep 1
  fi

  local interactive_user="$(/usr/bin/stat -f '%u' /dev/console)"

  pgrep "${NOTIFICATION_SERVER_NAME}" > /dev/null 2>&1
  if [[ $? -eq 0 ]] && [[ "${interactive_user}" != "" ]]; then
    echo "Stopping the notification server"

    launchctl asuser "${interactive_user}" launchctl "com.trailofbits.sinter.notification-server"
    if [[ $? -ne 0 ]] ; then
      # It's not ideal, but this is not a fatal error
      echo "Failed to stop the notification server"
    fi

    sleep 1
  fi

  if [[ -f "${AUTHORIZATION_DAEMON_PLIST}" ]] ; then
    echo "Uninstalling the authorization daemon"

    launchctl unload "${AUTHORIZATION_DAEMON_PLIST}"
    if [[ $? -ne 0 ]] ; then
      echo "Failed to unload the authorization daemon"
      return 1
    fi

    sleep 1
    rm "${AUTHORIZATION_DAEMON_PLIST}"
  fi

  if [[ -f "${NOTIFICATION_SERVER_PLIST}" ]] ; then
    echo "Uninstalling the notification server"

    launchctl unload "${NOTIFICATION_SERVER_PLIST}"
    if [[ $? -ne 0 ]] ; then
      echo "Failed to unload the notification server"
      return 1
    fi

    sleep 1
    rm "${NOTIFICATION_SERVER_PLIST}"
  fi

  pgrep "${SINTER_DAEMON_NAME}" > /dev/null 2>&1
  if [[ $? -eq 0 ]] ; then
    echo "The authorization daemon appears to be still running. Aborting"
    return 1
  fi

  pkgutil --pkgs | grep "com.trailofbits.Sinter.DefaultConfiguration" > /dev/null 2>&1
  if [[ $? -eq 0 ]] ; then
    echo "Uninstalling the DefaultConfiguration package"

    pkgutil --forget "com.trailofbits.Sinter.DefaultConfiguration"
    if [[ $? -ne 0 ]] ; then
      echo "Failed to uninstall the package"
      return 1
    fi
  fi

  pkgutil --pkgs | grep "com.trailofbits.Sinter.ApplicationBundle" > /dev/null 2>&1
  if [[ $? -eq 0 ]] ; then
    echo "Uninstalling the ApplicationBundle package"

    pkgutil --forget "com.trailofbits.Sinter.ApplicationBundle"
    if [[ $? -ne 0 ]] ; then
      echo "Failed to uninstall the package"
      return 1
    fi
  fi

  echo "Deleting: /Library/Application Support/Sinter"
  rm -rf "/Library/Application Support/Sinter"

  echo "Deleting: /Applications/Sinter.app"
  rm -rf "/Applications/Sinter.app"

  return 0
}

main $@
exit $?
