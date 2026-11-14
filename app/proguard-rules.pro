# Keep the manifest-referenced entry points (R8 keeps them by default,
# these are belt-and-braces so a release shrink can never drop them).
-keep class com.adshield.AdShieldVpnService { *; }
-keep class com.adshield.BootReceiver { *; }
-keep class com.adshield.MainActivity { *; }
