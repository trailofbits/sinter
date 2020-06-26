#!/usr/bin/env bash

main() {
  if [[ ! -d "Sinter.xcodeproj" ]] ; then
    printf "Please run this script from the repository root\n"
    return 1
  fi

  printf "Fetching the tags from git...\n"
  git fetch --all --tags 
  if [[ $? != 0  ]] ; then
    return 1
  fi

  export version="$(git describe --tags --abbrev=0)"
  local build="$(git describe --tags --always)"

  printf "Version: ${SINTER_VERSION} (${build})\n"
  
  local plist_path="Sinter/application/Info.plist"
  /usr/libexec/Plistbuddy -c "Set CFBundleShortVersionString ${version}" "${plist_path}"
  /usr/libexec/Plistbuddy -c "Set CFBundleVersion ${build}" "${plist_path}"
}

main $@
exit $?
