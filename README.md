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
## Prerequisites
It is important for Sinter.app to have the 'Full Disk Access' permission, otherwise it will fail to start. Do this by opening System Preferences, Security, Privacy tab, Full Disk Access. Check the item for `Sinter.app`.

The PKG installer will setup a LaunchDaemon that will automatically open Sinter on startup. Developers that may want to start the daemon from the shell must ensure that the **terminal they use also have the 'Full Disk Access' permission**, otherwise the EndpointSecurity API will return an error.

## Configuration
Sinter requires a configuration file to be present at `/etc/sinter/config.json`. This is how the settings look like, taken from the [example configuration](config/config.json) saved in the config folder:
```json
{
  "Sinter": {
    "decision_manager": "local",

    "allow_unsigned_programs": "true",
    "allow_invalid_programs": "true",
    "allow_unknown_programs": "true",
    "allow_expired_auth_requests": "true",

    "log_file_path": "/var/log/sinter.log",
    "config_update_interval": 600,
  },

  "SyncServerDecisionManager": {
    "server_address": "https://server_address:port",
    "machine_identifier": "machine_identifier",
  },

  "LocalDecisionManager": {
    "rule_database_path": "/etc/sinter/rules.json",
  }
}
```

The decision manager plugin can be selected by changing the `decision_manager` value. The **local** plugin will enable the **LocalDecisionManager** configuration section, pointing Sinter to use the local rule database present at the given path. It is possible to use a Santa-compatible sync-server, by using the **sync-server** plugin instead. This enables the **SyncServerDecisionManager** configuration section, where the server URL and machine identifier can be set.

## Enabling UI notifications
1. Install the notification server (the PKG installer will do this automatically): `sudo /Applications/Sinter.app/Contents/MacOS/Sinter --install-notification-server`
2. Start the agent: `/Applications/Sinter.app/Contents/MacOS/Sinter --start-notification-server`

## Configuring Sinter in MONITOR mode
Modes are not implemented in Sinter, as everything is rule-based. It is possible to implement the monitoring functionality by tweaking the following settings:

 - **allow_unsigned_programs**: allow applications that are not signed
 - **allow_invalid_programs**: allow applications that fail the signature check
 - **allow_unknown_programs**: automatically allow applications that are not covered by the active rule database
 - **allow_expired_auth_requests**: the EndpointSecurity API requires Sinter to answer to an authorization requests within an unspecified time frame (typically, less than a minute). Large applications, such as Xcode, will take a considerable amount of time to verify. Those executions are denied by default, and the user is expected to try again once the application has been verified. Setting this configuration to true changes this behavior so that those requests are always allowed.

## Rule format
Rule databases are written in JSON format. Here's an example database that allows the CMake application bundle from cmake.org:

```json
{
  "rules": [
    {
      "rule_type": "BINARY",
      "policy": "WHITELIST",
      "sha256": "BDD0AF132D89EA4810566B3E1E0D1E48BAC6CF18D0C787054BB62A4938683039",
      "custom_msg": "CMake"
    }
  ]
}
```

Sinter only supports **BINARY** rules for now, using either **WHITELIST** or **BLACKLIST** policies. The code directory hash value can be taken from the `codesign` tool output (example: `codesign -dvvv /Applications/CMake.app`). Note that even though the CLI tools can acquire the full SHA256 hash, the Kernel/EndpointSecurity API is limited to the first 20 bytes.

# License
Sinter is licensed and distributed under the AGPLv3 license. [Contact us](mailto:opensource@trailofbits.com) if you're looking for an exception to the terms.
