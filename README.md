# Sinter

Sinter is a 100% user-mode endpoint security agent for macOS 10.15 and above, written in the safe-by-design Swift programming language.

## Features

(Work in progress)
- MONITOR mode: captures process execution events and records them to a log on the local filesystem.
- Process execution whitelisting and blacklisting
 - by certificate Team ID
 - by hash
 - by executable file path
- Sync server support (compatible with the Moroz sync-server for Santa clients)

## How to Run (if built from source)

Sinter uses the Endpoint Security API in macOS 10.15 and above, meaning it must be code-signed with an Apple-issued "Distribution" signing certificate and provisioning profile that includes the Endpoint Security entitlement, which requires a manual application to Apple for approval. If you cannot sign with such a certificate, then you must disable SIP if you want to run Sinter built from source. To disable SIP (*not recommended except on a test system*):

Schedule a Recovery Mode reboot:

`$ sudo nvram "recovery-boot-mode=unused"; sudo reboot recovery`

From Recovery Mode, launch Utilities -> Terminal. Disable SIP, and boot back into regular macOS:

`$ csrutil disable; reboot`

To confirm that SIP is disabled:

`$ csrutil status`

Finally, to run Sinter, do not double-click the `Sinter` app bundle in Finder. Rather, launch the daemon directly:

`$ sudo Sinter.app/Contents/Library/SystemExtensions/com.trailofbits.sinter.systemextension`

In this version, it outputs events to stdout.

## How to Build

Sinter builds on macOS 10.15 or above.

### Install the Prerequisites

First, install [Xcode 11.4 or newer](https://apps.apple.com/us/app/xcode/id497799835?mt=12)

Install the Xcode command-line tools as well. One way to do this is:

`$ xcode-select --install`

### Set your Apple code-signing identity (required)

With the Xcode project open, enter the top-level project settings, and navigate to `Signing & Capabilities`. Here, configure your signing certificate and identity information.

### Apply for EndpointSecurity entitltements for your code-signing identity (optional, required for distribution)

To be able to distribute a macOS application that uses the `EndpointSecurity` API, as Sinter does, requires building and signing with a Distribution certificate from an Apple Developer Account that has been approved for the `EndpointSecurity` entitlement. Note that only a Team Account *owner* can apply for this entitlement.

### Build with Xcode at the command line

From the Sinter directory:

`$ xcodebuild -scheme Sinter -configuration Release`

Optional: you may need to set the command-line tools to the full Xcode, first, then try the above command again:

`$ sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer`

## Configure and Run Sinter

Sinter requires a configuration file to be present at `/etc/sinter/config.json`. An example is provided in the source tree at `./config/config.json`.

After building, from the build directory (`cd` to the build directory seen in the `--destination` output of the `xcodebuild` step):

`sudo ./Sinter.app/Contents/Library/SystemExtensions/com.trailofbits.sinter.daemon.systemextension/Contents/MacOS/com.trailofbits.sinter.daemon`

*In order to be launched as a LaunchDaemon*, "Full Disk Access" must also be enabled on `Sinter.app`. Do this by opening System Preferences, Security, Privacy tab, Full Disk Access. Check the item for `Sinter.app`.

## License

Sinter is licensed and distributed under the AGPLv3 license. [Contact us](mailto:opensource@trailofbits.com) if you're looking for an exception to the terms.
