#!/usr/bin/env bash

main() {
  if [[ $(countInvalidTeamIDs) != 0 ]] ; then
    echo "Found one or more invalid signing Team IDs configured"
    return 1
  fi

  return 0
}

listInvalidTeamIDs() {
  find . -type d -name '*.xcodeproj' | while read project_path ; do
    grep -r 'DEVELOPMENT_TEAM = ' "${project_path}" | grep -v '""'
  done
}

countInvalidTeamIDs() {
  listInvalidTeamIDs | wc -l | awk '{ print $1 }'
}

main $@
exit $?

