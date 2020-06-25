# Sinter

Sinter is a 100% user-mode endpoint security agent for macOS 10.15 and above, written in the safe-by-design Swift programming language. 

## Features

Sinter uses the user-mode EndpointSecurity API to subscribe to and receive authorization callbacks from the macOS kernel, for a set of security-relevant event types. The current version of Sinter supports allowing/blocking process executions; future versions will support other kinds of events like file event, socket event, and kernel event. 

- MONITOR mode: watch process execution events and record them to a structured-format log file
- Process execution allow-listing and deny-listing
   - by certificate Team ID
   - by hash
   - by executable file path
- Sync server support (compatible with the Moroz sync-server for Santa clients)

## Anti-Features

* Uses no kernel extensions, which will be officially deprecated in macOS 11 Big Sur
* Does not support legacy macOS (does not support 10.14 or older)
* No legacy codebase, no third-party library dependencies
* No components built with memory-unsafe programming languages
* Not an anti-malware or anti-virus. No signatures database. Blocks only what you tell it to block using rules.

## Configure and Run Sinter

Sinter requires a configuration file to be present at `/etc/sinter/config.json`. An example is provided in the source tree at `./config/config.json`.

After installing Sinter, "Full Disk Access" must also be enabled on `Sinter.app`. Do this by opening System Preferences, Security, Privacy tab, Full Disk Access. Check the item for `Sinter.app`.

## How to Build from Source

Because Sinter uses the EndpointSecurity API, it must be code-signed with an appropriate Apple-issued "Distribution" signing certificate and a corresponding provisioning profile that includes the EndpointSecurity entitlement, then also notarized. Code-signing for the EndpointSecurity entitlement requires a manual application to Apple for approval for the required provisioning profile. If you cannot sign with such a certificate, then you must disable SIP if you want to build Sinter from source and run locally. To disable SIP (*not recommended except on a test system*):

Schedule a Recovery Mode reboot:

`$ sudo nvram "recovery-boot-mode=unused"; sudo reboot recovery`

From Recovery Mode, launch Utilities -> Terminal. Disable SIP, and boot back into regular macOS:

`$ csrutil disable; reboot`

To confirm that SIP is disabled:

`$ csrutil status`

Finally, to run Sinter, do not double-click the `Sinter` app bundle in Finder. Rather, launch the daemon directly:

`$ sudo Sinter.app/Contents/Library/SystemExtensions/com.trailofbits.sinter.systemextension`

Run this way, it outputs events to stdout. When run via the default install method, it includes a configuration that also redirects `stdout` and `stderr` to logs in `/var/db/sinter/`. Logs are updated every 2 minutes. View `Console.app` for live logging.

## How to Build

Sinter builds on macOS 10.15 or above.

### Install the Prerequisites

First, install [Xcode 11.4 or newer](https://apps.apple.com/us/app/xcode/id497799835?mt=12)

Install the Xcode command-line tools as well. One way to do this is:

`$ xcode-select --install`

### Set your Apple code-signing identity (required)

With the Xcode project open, enter the top-level project settings, and navigate to `Signing & Capabilities`. Here, configure your signing certificate and identity information.

### Apply for EndpointSecurity entitltements for your code-signing identity (optional, required for distribution)

To be able to distribute a macOS application that uses the `EndpointSecurity` API, as Sinter does, requires building and signing with a Distribution certificate from an Apple Developer Account that has been approved for the `EndpointSecurity` entitlement. Note that only a Team Account *owner* can apply for this entitlement. [Apply here](https://developer.apple.com/system-extensions/), at the "Request an Entitlement" link.

### Build with Xcode at the command line

From the Sinter directory:

`$ xcodebuild -scheme Sinter -configuration Release`

Optional: you may need to set the command-line tools to the full Xcode, first, then try the above command again:

`$ sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer`

## License

Sinter is licensed and distributed under the AGPLv3 license. [Contact us](mailto:opensource@trailofbits.com) if you're looking for an exception to the terms.
