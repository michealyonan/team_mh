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
