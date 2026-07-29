{ pkgs ? import <nixpkgs> {
    config = {
      android_sdk.accept_license = true;
      allowUnfree = true;
    };
  }
}:

let
  androidComposition = pkgs.androidenv.composeAndroidPackages {
    platformVersions = [ "35" ];
    # AGP also resolves 34.0.0 while configuring this upstream checkout.
    buildToolsVersions = [ "34.0.0" "35.0.0" ];
    includeNDK = true;
    ndkVersions = [ "27.2.12479018" ];
    cmakeVersions = [ "3.22.1" ];
  };
  androidSdk = androidComposition.androidsdk;
in
pkgs.mkShell {
  packages = [
    pkgs.jdk21
    androidSdk
  ];

  shellHook = ''
    export JAVA_HOME=${pkgs.jdk21}
    export ANDROID_HOME=${androidSdk}/libexec/android-sdk
    export ANDROID_SDK_ROOT="$ANDROID_HOME"
    export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.2.12479018"
    export GRADLE_OPTS="$GRADLE_OPTS -Dorg.gradle.project.android.aapt2FromMavenOverride=$ANDROID_HOME/build-tools/35.0.0/aapt2"

    echo "JDK: $JAVA_HOME"
    echo "Android SDK: $ANDROID_HOME"
    echo "Android NDK: $ANDROID_NDK_HOME"
  '';
}
