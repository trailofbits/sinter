# Sinter

CI: [![Build Status](https://app.bitrise.io/app/7981426cfe90b436/status.svg?token=nUfXVprK5okMCcFXeOuwzg&branch=master)](https://app.bitrise.io/app/7981426cfe90b436)

Sinter is a 100% user-mode endpoint security agent for macOS 10.15 and above, written in Swift.

## Table of Contents

- [Purpose](#purpose)
- [Features](#features)
- [Anti-Features](#anti-features)
- [Getting Started](#quickstart)
- [How to Build from Source](#build-from-source)
- [License](#license)

## Purpose <a name = "purpose"></a>

The first open-source macOS solution for allowing/denying processes was [Google's Santa](https://github.com/google/santa). We at Trail of Bits are fans of Santa, and [have contributed to its codebase in the past](https://github.com/google/santa/pulls?q=is%3Apr+is%3Aclosed+author%3Aalessandrogario). However, being developed at Google, it primarily serves Google's needs. The best available configuration and management server ("sync server") for Santa [is tightly integrated with Google Cloud Platform](https://github.com/google/upvote), which not everyone uses. 

We often wondered if we could implement a simpler design from scratch, in strictly user-mode, with a modern programming language that avoids the potential for memory-corruption security vulnerabilities. We wanted it to be cloud-vendor-neutral with regard to its management servers. And we think an endpoint agent of this kind could do much more than just allowing and denying process events. So we began to develop Sinter.<sup>[1](#nameFootnote)</sup>

## Features <a name = "features"></a>

Sinter uses the user-mode EndpointSecurity API to subscribe to and receive authorization callbacks from the macOS kernel, for a set of security-relevant event types. The current version of Sinter supports allowing/blocking process executions; future versions will support other kinds of events like file event, socket event, and kernel event.

- Process execution allow-listing and deny-listing
  - by code directory hash (aka "CD hash")
- MONITOR mode: track (but allow) process execution events and record them to a structured-format log file
- Sync server support (currently compatible with the Moroz sync-server for Santa clients)
- Blocking configured with a JSON-based database provided either locally or by sync-server
- Structured logging to the local filesystem

Planned upcoming features:

- Additional process execution blocking rules
  - by executable file path
  - by certificate Team ID

## Anti-Features <a name = "anti-features"></a>

- Uses no kernel extensions, which will be officially deprecated in macOS 11 Big Sur
- Does not support legacy macOS (does not support 10.14 or older)
- No legacy codebase, no third-party library dependencies
- No components built with memory-unsafe programming languages
- Not an anti-malware or anti-virus. No signatures database. Blocks only what you tell it to block, using rules.

## Getting Started <a name = "quickstart"></a>

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

It is possible to configure Sinter to log and optionally block applications that have not been started from an allowed folder.

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

## How to Build from Source <a name = "build-from-source"></a>

Sinter builds on macOS 10.15 or above.

### Disable SIP on a Dev System

Because Sinter uses the EndpointSecurity API, it must be code-signed with an appropriate Apple-issued "Distribution" signing certificate and a corresponding provisioning profile that includes the EndpointSecurity entitlement, then also notarized. Code-signing for the EndpointSecurity entitlement requires a manual application to Apple for approval for the required provisioning profile. If you cannot sign with such a certificate, then you must disable SIP if you want to build Sinter from source and run locally. To disable SIP (*not recommended except on a test system*):

Schedule a Recovery Mode reboot:

`$ sudo nvram "recovery-boot-mode=unused"; sudo reboot recovery`

From Recovery Mode, launch Utilities -> Terminal. Disable SIP, and boot back into regular macOS:

`$ csrutil disable; reboot`

To confirm that SIP is disabled:

`$ csrutil status`

### Install the Prerequisites

First, install [Xcode 11.4 or newer](https://apps.apple.com/us/app/xcode/id497799835?mt=12)

Install the Xcode command-line tools as well. One way to do this is:

`$ xcode-select --install`

(Optional, if building the installer pkg) The Sinter project uses CMake to automate the post-build packaging and notarization steps. Install the [latest version of CMake](https://cmake.org/).

### Set your Apple code-signing identity (required)

With the Xcode project open, enter the top-level project settings, and navigate to `Signing & Capabilities`. Here, configure your signing certificate and identity information.

### Apply for EndpointSecurity entitltements for your code-signing identity (optional, required for distribution)

To be able to distribute a macOS application that uses the `EndpointSecurity` API, as Sinter does, requires building and signing with a Distribution certificate from an Apple Developer Account that has been approved for the `EndpointSecurity` entitlement. Note that only a Team Account *owner* can apply for this entitlement. [Apply here](https://developer.apple.com/system-extensions/), at the "Request an Entitlement" link.

### Build with Xcode at the command line

From the Sinter directory:

`$ xcodebuild -scheme Sinter -configuration Release`

Optional: you may need to set the command-line tools to the full Xcode, first, then try the above command again:

`$ sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer`

### Notarize and Generate the Package Installer (optional)

`$ cd packaging && mkdir build && cd build && cmake ..`

### Running the Sinter Daemon in the Terminal

Finally, to run Sinter and observe the console output in realtime, do not double-click the `Sinter` app bundle in Finder. Rather, launch the daemon directly:

`$ sudo Sinter.app/Contents/Library/SystemExtensions/com.trailofbits.sinter.systemextension`

Run this way, it outputs events to stdout. When run via the default install method, it includes a launchd daemon configuration that also redirects `stdout` and `stderr` to logs in `/var/db/sinter/`. Logs are updated every 2 minutes. View `Console.app` for live logging.

**Note**: to run Sinter in the CLI this way, the `terminal.app` process must also have the Full Disk Access permission, in System Preferences -> Security -> Privacy tab.

## License <a name = "license"></a>

Sinter is licensed and distributed under the AGPLv3 license. [Contact us](mailto:opensource@trailofbits.com) if you're looking for an exception to the terms.

<a name="nameFootnote">Sinter is short for "Sinter Klausen," another name for Santa Claus</a>