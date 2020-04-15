# Sinter's macOS installer-builder

The scripts in this directory generate macOS installers (pkg files) for Sinter.

They are modified/forked from https://github.com/KosalaHerath/macos-installer-builder and retain their original LICENSE file separate from the main LICENSE for Sinter.

## How to build the pkg file:

- Begin with Sinter.app (either the Debug build or the Release build as needed) and its `launchd` plist file placed in ./macOS-x64/application/
- Open a terminal in this directory and:
```bash
cd macOS-x64
./build-macos-x64.sh Sinter 0.1.0
```
where `Sinter` is the product name and `0.1.0` is a version string.
- Find the resulting pkg installer in ./macOS-x64/target/pkg/