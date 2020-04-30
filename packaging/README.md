# Sinter's macOS installer-builder

The scripts in this directory generate macOS installers (pkg files) for Sinter.

They are modified/forked from https://github.com/KosalaHerath/macos-installer-builder and retain their original LICENSE file separate from the main LICENSE for Sinter.

## How to build the pkg file:

- Copy Sinter.app (either the Debug build or the Release build as needed) to `./macOS-x64/application/`
- Edit the config file in `./macOS-x64/config/config.json.example` if desired
- Open a terminal in this directory and:
```bash
cd macOS-x64
./build-macos-x64.sh Sinter 0.1.0
```
where `Sinter` is the product name (where it will be installed under `/Applications`) and `0.1.0` is a version string (currently unused).
- Find the resulting unsigned pkg installer in `./macOS-x64/target/pkg/` or, if you chose to sign the package, in `./macOS-x64/target/pkg-signed`. 
