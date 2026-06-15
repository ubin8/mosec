# Mobile Analysis

MoSec already includes Android-focused checks and structure for mobile analysis.

## Android support today

- Android manifest parsing
- Exported activities
- Exported broadcast receivers
- Dangerous permissions
- Insecure SharedPreferences usage

## Android metadata MoSec reads

- package name
- shared user id
- uses-permission entries
- uses-feature entries
- application flags such as debuggable, allowBackup, and cleartext traffic
- component export state and permissions

## What comes next

The codebase is structured so future mobile rules can add:

- insecure SQLite usage
- WebView risks
- custom URL scheme risks
- iOS entitlements
- ATS checks
- Keychain usage analysis

## Practical note

Mobile checks are reported in the same finding model as web and secret findings, so they can be filtered and exported in the same way.

