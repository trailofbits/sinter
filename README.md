# Sinter

[![Build Status](https://app.bitrise.io/app/7981426cfe90b436/status.svg?token=nUfXVprK5okMCcFXeOuwzg&branch=master)](https://app.bitrise.io/app/7981426cfe90b436)

Sinter is a 100% user-mode endpoint security agent for macOS 10.15 and above, written in Swift.

Sinter uses the user-mode EndpointSecurity API to subscribe to and receive authorization callbacks from the macOS kernel, for a set of security-relevant event types. The current version of Sinter supports allowing/denying process executions; in future versions we intend to support other types of events such as file, socket, and kernel events.

**Sinter is a work-in-progress.** Feedback is welcome. If you are interested in contributing or sponsoring us to help achieve its potential, [let's get in touch](https://www.trailofbits.com/contact/).

## Features

- Allow or deny process execution by code directory hash (aka "CD hash")
  - option to deny all unknown programs (any program that is not explicitly allowed)
  - option to deny all unsigned programs
  - option to deny all programs with invalid signatures
- "monitor" mode to track and log (but allow) all process execution events
- Accepts allow/deny rules from a Santa sync-server
- Configure deny rules in JSON, provided locally or by a sync-server
- Log to the local filesystem in a structured JSON format

Planned upcoming features:
- Deny process execution by [executable file path](https://github.com/trailofbits/sinter/issues/17)
- Deny process execution by [certificate Team ID](https://github.com/trailofbits/sinter/issues/4)

## Anti-Features

- Does not use kernel extensions (which will be officially deprecated in macOS 11 Big Sur)
- Does not support legacy macOS (10.14 or older)
- Does not use any memory unsafe code
- Limits third-party library dependencies
- Not an anti-malware or anti-virus. No signature database. Denies only what you tell it to deny, using rules.

## Background

The first open-source macOS solution for allowing/denying processes was [Google Santa](https://github.com/google/santa). We're fans of Santa, and [have contributed to its codebase in the past](https://github.com/google/santa/pulls?q=is%3Apr+is%3Aclosed+author%3Aalessandrogario). For a long time, however, many in the macOS community have asked for an open-source solution to track and manage _more_ than just process events.

We saw the ideal platform to build such a capability with the EndpointSecurity API in macOS 10.15. Starting from the ground-up around a strictly user-mode API meant that we could attempt a simpler design, and use a modern programming language with safer memory handling and [better performance](https://www.apple.com/swift/). Thus, we set out to develop Sinter, short for "Sinter Klausen," another name for Santa Claus.

## Getting Started

Download and install the latest version of Sinter using the `pkg` installer link from the [Releases](https://github.com/trailofbits/sinter/releases) page.

After installing Sinter, you must enable the "Full Disk Access" permission for `Sinter.app`. Do this by opening System Preferences, Security, Privacy tab, Full Disk Access. Check the item for `Sinter.app`. If using MDM, you can automatically enable this permission on your endpoints, and no user interaction will be required.

### Configuration

Sinter requires a configuration file to be present at `/etc/sinter/config.json`. An example is provided in the source tree at `./config/config.json`:

```json
{
  "Sinter": {
    "decision_manager": "local",
    "logger": "filesystem",

    "allow_unsigned_programs": "true",
    "allow_invalid_programs": "true",
    "allow_unknown_programs": "true",
    "allow_expired_auth_requests": "true",
    "allow_misplaced_applications": "true",

    "config_update_interval": 600,

    "allowed_application_directories": [
      "/bin",
      "/usr/bin",
      "/usr/local/bin",
      "/Applications",
      "/System",
      "/usr/sbin",
      "/usr/libexec",
    ],
  },
  
  "FilesystemLogger": {
    "log_file_path": "/var/log/sinter.log",
  },

  "RemoteDecisionManager": {
    "server_url": "https://server_address:port",
    "machine_identifier": "identifier",
  },

  "LocalDecisionManager": {
    "rule_database_path": "/etc/sinter/rules.json",
  }
}
```

The decision manager plugin can be selected by changing the `decision_manager` value. The **local** plugin will enable the **LocalDecisionManager** configuration section, pointing Sinter to use the local rule database present at the given path. It is possible to use a Santa-compatible sync-server, by using the **sync-server** plugin instead. This enables the **RemoteDecisionManager** configuration section, where the server URL and machine identifier can be set.

There are two logger plugins currently implemented:

1. **filesystem**: Messages are written to file, using the path specified at FilesystemLogger.log_file_path
2. **unifiedlogging**: Logs are emitted using the Unified Logging, using **com.trailofbits.sinter** as subsystem.

### Allowed application directories

It is possible to configure Sinter to log and optionally deny applications that have not been started from an allowed folder.

- **allow_misplaced_applications**: If set to true, misplaced applications will only generate a warning. If set to false, any execution that does not starts from a valid path is denied.
- **allowed_application_directories**: If non-empty, it will be used to determine if applications are placed in the wrong folder.

### Enabling UI notifications

1. Install the notification server (the PKG installer will do this automatically): `sudo /Applications/Sinter.app/Contents/MacOS/Sinter --install-notification-server`
2. Start the agent: `/Applications/Sinter.app/Contents/MacOS/Sinter --start-notification-server`

### Configuring Sinter in MONITOR mode

Modes are not implemented in Sinter, as everything is rule-based. It is possible to implement the monitoring functionality by tweaking the following settings:

- **allow_unsigned_programs**: allow applications that are not signed
- **allow_invalid_programs**: allow applications that fail the signature check
- **allow_unknown_programs**: automatically allow applications that are not covered by the active rule database
- **allow_expired_auth_requests**: the EndpointSecurity API requires Sinter to answer to an authorization requests within an unspecified time frame (typically, less than a minute). Large applications, such as Xcode, will take a considerable amount of time to verify. Those executions are denied by default, and the user is expected to try again once the application has been verified. Setting this configuration to true changes this behavior so that those requests are always allowed.

### Rule format

Rule databases are written in JSON format. Here's an example database that allows the CMake application bundle from cmake.org:

```json
{
  "rules": [
    {
      "rule_type": "BINARY",
      "policy": "ALLOWLIST",
      "sha256": "BDD0AF132D89EA4810566B3E1E0D1E48BAC6CF18D0C787054BB62A4938683039",
      "custom_msg": "CMake"
    }
  ]
}
```

Sinter only supports **BINARY** rules for now, using either **ALLOWLIST** or **DENYLIST** policies. The code directory hash value can be taken from the `codesign` tool output (example: `codesign -dvvv /Applications/CMake.app`). Note that even though the CLI tools can acquire the full SHA256 hash, the Kernel/EndpointSecurity API is limited to the first 20 bytes.

## Building from Source

Building Sinter requires certain code-signing certificates and entitlements that Apple must grant your organization. However, Sinter can still be built from source and run locally on a test system with SIP disabled. For instructions, see the [Sinter wiki](https://github.com/trailofbits/sinter/wiki).

## License

Sinter is licensed and distributed under the AGPLv3 license. [Contact us](mailto:opensource@trailofbits.com) if you're looking for an exception to the terms.
