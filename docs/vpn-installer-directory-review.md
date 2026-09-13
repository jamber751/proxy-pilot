# Installer directory enumeration review

The uninstall allowlist enumerator now opens `.` relative to the protected
installation directory to obtain an independent directory cursor. It no longer
duplicates a descriptor whose open-file-description offset could be shared.

Each `readdir` call resets and checks `errno`. A returned Darwin `dirent` name is
decoded directly from its variable-size record using the `d_name` offset,
`d_namlen`, and `d_reclen`. The decoder requires 1–1023 name bytes, space for the
terminal NUL inside the record, an actual terminal NUL, valid UTF-8, and no
embedded NUL or slash. It never materializes the imported 1024-byte `d_name`
tuple, avoiding the sanitizer-detected overread beyond a short record.

The existing exact uninstall allowlist and removal ordering are unchanged. A
targeted sanitizer fixture creates 600 disposable removable names, first drives
the supplied directory descriptor's shared cursor to EOF, and then calls the
enumerator twice. It observed both complete 600-name results without an Address
Sanitizer report in **35.271 seconds**. This is direct directory-enumeration
coverage, not an ASan uninstall or activation result.

The first normal installer suite compiled the production and test variants but
its live per-user launchd regression was not green: **9 of 36 tests
passed and 27 failed in 49.845 seconds**. Every failure shown was an initial
fixture activation returning `VPNActivationFailure(phase: start,
cleanupConfirmed: true)` before the uninstall enumerator was reached. This is an
exact observation, not itself attribution to the sanitizer or production change.
The agent subsequently confirmed those attempts used default sandbox permissions.

The root agent repeated the complete final suite with explicitly approved
`require_escalated` execution for disposable per-user launchd tests: **36/36
passed in 59.604 seconds**, including direct ASan enumeration, real fixture
install/update/uninstall, foreign-file preservation, journal boundaries and
identity refusals. No production check was relaxed. This repeat distinguishes
the earlier sandbox-restricted failures from final acceptance; it does not claim
root/system installation coverage. The final test fixture also compiles both
production architectures without test seams. No root/system service or real
installation was used. Only the `VPN_INSTALLER_TESTING` entry for deterministic
enumeration was added after the final application build; production enumeration
code remained unchanged and was covered by the later production compiles.
