# Tether for Android and iOS

Use Tether from your phone without opening a browser first. The apps are the Tether web app
(`../app`), bundled onto the device with [Capacitor](https://capacitorjs.com). Every screen works
the same as on the web: sessions, chat, approvals, live terminal and "Continue in…". End-to-end
encryption is unchanged; your key stays on the phone.

## Settings: which relay to use

The web app always talks to the relay that served it. An app has no such relay, so it asks for
one. **Settings** (the gear in the top bar, or **Connection** on the sign-in screen) holds
connection profiles:

| Field | What to put there |
|---|---|
| Name | Anything, e.g. Home, Work, Staging |
| Relay URL | The address you open Tether at in a browser, e.g. `https://tether.example.com` |
| Invite code | Only if that relay needs one to create accounts |

Add one profile per environment and switch between them. Each profile has its own sign-in on the
phone. **Test** checks that the address is a working relay before you save.

Addresses typed without `http://` or `https://`:

- A bare IP or `localhost` (e.g. `192.168.1.20:8787`) is treated as a relay on your LAN and uses
  `http://`.
- A domain name uses `https://`.

For a relay on your own computer:

- **Android emulator:** `http://10.0.2.2:8787`
- **Phone on the same Wi-Fi:** `http://<computer's LAN IP>:8787`. Start the relay with
  `HOST=0.0.0.0 tetherd relay`.

## Install

**Android.** Install `dist/Tether-android-0.1.0-debug.apk` on the phone. You'll need to allow
installs from that source. This is a debug-signed build for sideloading and testing. The Play
Store needs a release build signed with your own key; see below.

**iOS.** There is no prebuilt file. Apple only allows installs of apps built and signed with an
Apple developer identity, so build it on a Mac with Xcode, as below.

## Build

Needs Node 22+. Run everything from `mobile/`, after `npm install`.

```sh
npm run sync          # copy ../app into www/ and update both native projects
```

**Android.** Needs JDK 21 and the Android SDK (platform 35, build-tools 35):

```sh
npm run android:apk   # -> android/app/build/outputs/apk/debug/app-debug.apk
npm run android:run   # build, install and launch on a connected device or emulator
```

To build a Play Store release, create a keystore, add a `signingConfigs.release` block to
`android/app/build.gradle`, then run `cd android && ./gradlew bundleRelease`.

**iOS.** Needs full Xcode (from the App Store) and an Apple ID:

```sh
npm run ios:open      # sync, then open ios/App/App.xcodeproj in Xcode
```

In Xcode:

1. Select the **App** target → **Signing & Capabilities** → choose your Team.
2. Run on a simulator or on your iPhone.
3. To share the app, use **Product → Archive** for TestFlight or ad-hoc distribution.

The project uses Swift Package Manager, so CocoaPods is not needed.

After changing anything in `../app`, run `npm run sync` again before rebuilding.

## How it's wired

- `capacitor.config.json` turns on `CapacitorHttp`, so API calls go through the phone's native
  HTTP stack. Any existing relay works this way; relays don't need CORS headers.
- Android allows cleartext `http` (`usesCleartextTraffic`), and iOS allows it through
  `NSAppTransportSecurity`. Both exist so LAN and self-hosted relays work. Message content is
  end-to-end encrypted by the app either way.
- `app/app.js` reads the relay from the active profile when running natively
  (`window.Capacitor.isNativePlatform()`). In a browser it keeps using the page's own origin.
