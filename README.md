# Sinter

Sinter is a 100% user-mode endpoint security agent for macOS 10.15 and above, written in the Swift programming language.

# Features

This program is under heavy development, and new features will be added really soon! Currently, Sinter is able to block applications based on the code directory hash value, using a JSON-based database that can be provided either locally or with a Santa-compatible sync-server.

Additional settings allow the user to choose whether to enable or disable unsigned and invalid programs, which can be used to mimic the MONITOR mode used by Santa.

# Building from source

## Requirements
Sinter uses the Endpoint Security API in macOS 10.15 and above, meaning it must be code-signed with an Apple-issued "Distribution" signing certificate and provisioning profile that includes the Endpoint Security entitlement, which requires a manual application to Apple for approval. If you cannot sign with such a certificate, then you must disable SIP if you want to run Sinter built from source.

## Build instructions
From the Sinter directory:

`$ xcodebuild -scheme Sinter -configuration Release`

Optional: you may need to set the command-line tools to the full Xcode, first, then try the above command again:

`$ sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer`

# Running Sinter
## Configuration
Sinter requires a configuration file to be present at `/etc/sinter/config.json`. An [example configuration](config/config.json) is provided in the source tree.

It is important for Sinter.app to have the 'Full Disk Access' permission, otherwise it will fail to start. Do this by opening System Preferences, Security, Privacy tab, Full Disk Access. Check the item for `Sinter.app`.

The PKG installer will setup a LaunchDaemon that will automatically open Sinter on startup. Developers that may want to start the daemon from the shell must ensure that the terminal they use also have the 'Full Disk Access' permission, otherwise the EndpointSecurity API will return an error.

## Logging
Log files are located in the `/var/db/sinter` folder, and are flushed by launchd automatically once every 2 minutes.

# License
Sinter is licensed and distributed under the AGPLv3 license. [Contact us](mailto:opensource@trailofbits.com) if you're looking for an exception to the terms.
