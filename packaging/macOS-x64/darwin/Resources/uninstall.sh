#!/bin/bash

#Generate application uninstallers for macOS.

#Parameters
DATE=`date +%Y-%m-%d`
TIME=`date +%H:%M:%S`
LOG_PREFIX="[$DATE $TIME]"

#Functions
log_info() {
    echo "${LOG_PREFIX}[INFO]" $1
}

log_warn() {
    echo "${LOG_PREFIX}[WARN]" $1
}

log_error() {
    echo "${LOG_PREFIX}[ERROR]" $1
}

#Check running user
if (( $EUID != 0 )); then
    echo "Please run as root."
    exit
fi

echo "Welcome to Application Uninstaller"
echo "The following packages will be REMOVED:"
echo "  __PRODUCT__-__VERSION__"
while true; do
    read -p "Do you wish to continue [Y/n]?" answer
    [[ $answer == "y" || $answer == "Y" || $answer == "" ]] && break
    [[ $answer == "n" || $answer == "N" ]] && exit 0
    echo "Please answer with 'y' or 'n'"
done


#Need to replace these with install preparation script
VERSION=__VERSION__
PRODUCT=__PRODUCT__

echo "Application uninstalling process started"
# remove launchd items
/Applications/Sinter.app/Contents/MacOS/Sinter --uninstall-daemon
if [ $? -eq 0 ]
then
  echo "[1/4] [DONE] Successfully deleted application"
else
  echo "[1/4] [ERROR] Could not delete application" >&2
  exit 1
fi

/Applications/Sinter.app/Contents/MacOS/Sinter --uninstall-notification-server
if [ $? -eq 0 ]
then
  echo "[2/4] [DONE] Successfully deleted application"
else
  echo "[2/4] [ERROR] Could not delete application" >&2
  exit 1
fi

# remove application bundle
find "/Applications/" -name "__PRODUCT__" | xargs rm
if [ $? -eq 0 ]
then
  echo "[3/4] [DONE] Successfully deleted Application"
else
  echo "[3/4] [ERROR] Could not delete Application" >&2
  exit 1
fi

# forget from pkgutil
pkgutil --forget "org.$PRODUCT.$VERSION" > /dev/null 2>&1
if [ $? -eq 0 ]
then
  echo "[4/4] [DONE] Successfully deleted application informations"
else
  echo "[4/4] [ERROR] Could not delete application informations" >&2
  exit 1
fi

echo "Application uninstall process finished"
exit 0
