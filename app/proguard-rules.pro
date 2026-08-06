# Bouncy Castle se registra vía Java Security SPI; no ofuscar sus clases.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
