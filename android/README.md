# Team MH Android wrapper (APK)

WebView wrapper للموقع https://team-mh.michealuonanayad.workers.dev/

## Files
- `AndroidManifest.xml` - package com.michealyonan.teammh, portrait lock, minSdk 24 / targetSdk 34
- `src/com/michealyonan/teammh/MainActivity.java` - the whole app: WebView pointing at HOME_URL
- `res/` - launcher icons + strings

## Build (command line, no Android Studio needed)
Needs Android SDK (platform android-34 + build-tools 34.0.0) and JDK 17:

    javac -encoding UTF-8 -cp $ANDROID_JAR -sourcepath gen -d classes src/com/michealyonan/teammh/MainActivity.java
    d8 --lib $ANDROID_JAR --output build/dex $(find classes -name '*.class')
    aapt2 compile --dir res -o build/compiled.zip
    aapt2 link -o build/app-unsigned.apk -I $ANDROID_JAR --manifest AndroidManifest.xml --min-sdk-version 24 --target-sdk-version 34 build/compiled.zip
    (cd build/dex && zip ../app-unsigned.apk classes.dex)
    apksigner sign --ks team-mh.keystore --ks-key-alias team-mh-key --out app.apk build/app-unsigned.apk

Then copy the signed APK to the repo root as `app.apk` - the site serves it at /app.apk.

## Keystore
The signing keystore (team-mh.keystore) and its passwords are NOT in this repo on purpose.
Every update MUST be signed with the same key or Android refuses the install.

## v2.0 (versionCode 6) - phone-session form agent
- Hidden second WebView runs assets/phone_form_agent.js: polls /api/forms/phone-poll
  (Bearer token read from the dashboard WebView's web storage, NOT cookies - the worker
  has no cookie auth), walks and submits the Google Form from the phone's own session.
- Google sign-in happens in the main WebView (accounts.google.com/docs.google.com are
  allowed in-app; the "; wv" marker is stripped from the UA or Google refuses sign-in).
- v2 signing key: team-mh-v2.keystore. The v1 key is LOST (v1 installs must uninstall first).
  v2 key password is in the owner's vault ("team_mh APK signing key v2"); the keystore
  itself is escrowed base64 in D1 settings key apk_keystore_v2 (admin-only endpoint
  /api/admin/apk-keystore). All future updates MUST use this key.
