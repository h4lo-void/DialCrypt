# R8 rules for the release build (isMinifyEnabled and isShrinkResources are on).
#
# Why these rules are wide: the app runs in three processes (default, ":secure" and ":call") and its
# non-UI code is reached by name from places R8 cannot see: the native library (JNI looks up
# NativeBridge by its class and method names), reflection, the Manifest, and the other processes
# (services and activities are started by class name through intents and the system). Renaming,
# removing or inlining any of that would break the app only on a release build. So the core, call,
# incoming and security packages are kept whole, with every member. Only the ui package and the third-party
# libraries are shrunk and optimized.

-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod,Exceptions

# Packages reached by JNI, reflection or another process.
-keep class io.github.h4lovoid.dialcrypt.core.** { *; }
-keep class io.github.h4lovoid.dialcrypt.call.** { *; }
-keep class io.github.h4lovoid.dialcrypt.incoming.** { *; }
-keep class io.github.h4lovoid.dialcrypt.security.** { *; }

# Every native method keeps its class and its name, so the JNI symbols Java_io_github_h4lovoid_dialcrypt_... still resolve.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# Components declared in the Manifest (the ones in call and incoming are covered above).
-keep class io.github.h4lovoid.dialcrypt.ui.LauncherActivity { *; }
-keep class io.github.h4lovoid.dialcrypt.ui.SecureActivity { *; }

# Generated constants read by the code in the packages above.
-keep class io.github.h4lovoid.dialcrypt.BuildConfig { *; }
