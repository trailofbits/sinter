# Sinter's macOS installer-builder
The scripts in this directory generate macOS installers (pkg files) for Sinter.

## How to build the pkg file:

- Begin with Sinter.app (either the Debug build or the Release build as needed) and its `launchd` plist file placed in ./macOS-x64/application/
- Open a terminal in this directory and:
```bash
cd macOS-x64/application
./build-macos-x64.sh Sinter 0.1.0
```
- Find the resulting pkg installer in ./macOS-x64/target/pkg/