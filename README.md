# Coruna

The leaked exploit toolkit for various iOS versions. Extracted from `https://sadjd.mijieqi[.]cn/group.html`

Partially deobfuscated, symbolicated, and modified to load decrypted payloads by Claude (thanks @34306 for sponsor) and by hand.

These scripts are modified in a way that allows you to host them locally. Note that this only includes exploit chains for tested devices.

## Analysis
There are so many analysis by other people right now so I'm not doing it again, however I have a generated [ANALYSIS.md](ANALYSIS.md) specifically talking about decryption process and iOS payloads version table.

## Tested on
| Device| Version | WebKit exploit chain |
| :--- | --- | --- |
| iPhone 6s+ | 15.4.1 | jacurutu -> VariantB? |
| iPhone Xs Max | 16.5 | terrorbird -> seedbell -> VariantB |
| iPhone 15 Pro Max | 17.0 | cassowary -> seedbell_pre -> seedbell_17 -> VariantB |

## Finding krw offsets
```

LC_ALL=C ggrep -r -oba -P '[\x7F\x23\x03\xD5]?\xF6\x57\xBD\xA9\xF4\x4F\x01\xA9\xFD\x7B\x02\xA9\xFD\x83\x00\x91\xF3\x03\x02\xAA\xF5\x03\x00\xAA' entry1_type0x09.dylib



```
