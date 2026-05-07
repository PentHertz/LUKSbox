# macOS code-signing assets

Files in this directory are consumed by the **macOS codesign + notarize**
steps in `.github/workflows/release.yml` and (locally) by anyone signing
a `LUKSbox.app` bundle by hand.

## `entitlements.plist`

The hardened-runtime entitlements applied to `luksbox` and
`luksbox-gui` inside the `.app` bundle. Two entitlements only:

- `com.apple.security.cs.disable-library-validation` — required
  because LUKSbox bundles `libfido2` and its transitive dylibs
  (`libcbor`, `libcrypto`, `libssl`) into `Contents/Frameworks/`
  via `dylibbundler`. Those dylibs are signed by us
  (Developer ID Application), not by Apple. Without disabling
  library validation, `dyld` refuses to load any dylib whose
  Team ID does not match the main binary's, and the app fails
  at launch with `Library Validation failed`.

- `com.apple.security.device.usb` — `libfido2` opens USB-HID
  devices to talk to FIDO2 authenticators (YubiKey, Google Titan,
  SoloKey, Nitrokey). Without this entitlement, `hidd` refuses
  the `open()` call and the device list is empty.

**Deliberately NOT set** (smaller attack surface, faster Apple
notarisation review):

- `com.apple.security.cs.allow-jit`
- `com.apple.security.cs.allow-unsigned-executable-memory`
- `com.apple.security.cs.allow-jit-write-execute`
- `com.apple.security.cs.allow-dyld-environment-variables`
- `com.apple.security.cs.disable-executable-page-protection`

LUKSbox is pure Rust; no JIT, no W^X-violating mmap, no
`DYLD_*` dependency.

### Why no comments inside the .plist itself

`AMFI` (Apple Mobile File Integrity, the kernel side of code
signing) parses entitlements with a strict XML reader that
rejects `<!-- ... -->` comments inside the `<dict>` block,
even though `plutil` and `defaults` accept them. The result
is a confusing `AMFIUnserializeXML: syntax error near line N`
at codesign time. Comments live here in the README instead.

## `sign-and-notarize.sh` (not committed)

Local-mac signing helper, built into the workflow and not
duplicated here. To sign a `.app` by hand on your Mac:

```bash
APP="path/to/LUKSbox.app"
IDENTITY="Developer ID Application: Sebastien Dudek (XXXXXXXXXX)"

# Sign every nested dylib first
find "$APP/Contents/Frameworks" -type f \( -name "*.dylib" -o -name "*.so" \) \
    -print0 | xargs -0 -n1 codesign --force --timestamp --options runtime \
    --sign "$IDENTITY"

# Then the binaries
for bin in "$APP/Contents/MacOS"/*; do
    codesign --force --timestamp --options runtime \
        --entitlements dist/macos/entitlements.plist \
        --sign "$IDENTITY" "$bin"
done

# Then the bundle
codesign --force --timestamp --options runtime \
    --entitlements dist/macos/entitlements.plist \
    --sign "$IDENTITY" "$APP"

# Verify
codesign --verify --deep --strict --verbose=2 "$APP"
```

Notarise via `xcrun notarytool submit … --wait` and
`xcrun stapler staple` — see the `Notarize macOS .dmg` step
in `.github/workflows/release.yml` for the full invocation.
