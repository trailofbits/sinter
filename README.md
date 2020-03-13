# Sinter

Sinter is a 100% user-mode endpoint security agent for macOS 10.15 and above.

## Features

(Work in progress)

## How to Run

Current builds of Sinter require SIP to be disabled. To disable SIP (*not recommended except on a test system*):

Schedule a Recovery Mode reboot:

`$ sudo nvram "recovery-boot-mode=unused"; sudo reboot recovery`

From Recovery Mode, launch Utilities -> Terminal, and disable SIP:

`$ csrutil disable; reboot`

Check that SIP is disabled, and boot back into regular macOS:

`$ csrutil status`

Finally, to run Sinter:

`$ sudo sinter`

Sinter runs as a daemon. In this version it outputs events to the command line.

## How to Build

Sinter builds on macOS 10.15 or above.

### Install the Prerequisites

First, install [Xcode](https://apps.apple.com/us/app/xcode/id497799835?mt=12) and [Homebrew](https://brew.sh/). Then, install these build tool dependencies:

`brew install cmake ninja`

### Find your Apple code-signing identity (required)

`security find-identity -v -p codesigning`

Copy the appropriate "Apple Development" ID (the ascii-encoded hex value), and pass it to CMake at configure time: `-DSINTER_CODESIGN_IDENTITY:STRING=XXX"

### Apply for EndpointSecurity entitltements for your code-signing identity (optional, required for distribution)

To be able to distribute a macOS application that uses the `EndpointSecurity` API, as Sinter does, requires building and signing with a certificate from an Apple Developer Account that has been approved for the `EndpointSecurity` entitlement. Note that only a Team Account owner can apply for this entitlement.

### Build with CMake

From the Sinter directory:

`mkdir build && cd build && cmake -G Ninja .. && ninja`

## Run Sinter

After building, from the build directory:

`sudo ./sinter`

## License

Sinter is licensed and distributed under the AGPLv3 license. [Contact us](mailto:opensource@trailofbits.com) if you're looking for an exception to the terms.
