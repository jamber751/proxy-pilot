# Protected replacement executor binding

Date: 2026-09-13. Internal protected-copy update path only.

## Why this increment is needed

The journal coordinator already authenticates the exact running A executable.
However, A outside the two swap slots could still be running from a writable
external installation. Excluding self-replacement alone did not bind execution
to protected files. A replacement process must remain independent of the files
it exchanges.

Production exchange now requires three fixed, distinct directories below its
already-trusted private base:

```
executor/ProxyPilot.app   exact A, running executor; never exchanged
current/ProxyPilot.app    A before exchange, B after exchange
candidate/ProxyPilot.app  B before exchange, retained A after exchange
```

These are transaction/staging slots, not a new Applications installation layout.
No implementation here creates, copies, launches or installs an executor.

## Checks and lifetime

`VPNReplacementExecutor` opens the fixed executor directory without following
symlinks, binds its descriptor to the named entry and requires it to be distinct
from both application slots. The full staged-app inspector checks exact signed
A, both architecture pins, metadata, nested code/resources and protected modes.

The fixed main executable is opened component-by-component without following
symlinks. Its held device/inode must equal the file opened using the current
process's kernel-reported executable path; a different copy with the same
signature is not enough. Regular-file type and single-link identity are checked.
This complements, not replaces, the coordinator's dynamic current-A policy.

The opaque, in-memory binding owns its descriptors and full bundle observation.
Under the existing application namespace lease, every swap check repeats:

- Base-to-executor directory binding and separation from both slots.
- Complete exact-A observation, including resources and nested code.
- Fixed named executable versus held executable descriptor.
- Current-process path object versus that same executable descriptor.

Checks run before authorization, after drain, after exchange and on retry.
After an exchange has occurred or exact B/A has been recognized, subsequent
check failures remain `commitUncertain`; no inverse exchange is attempted.
Initial refusal before classifying the layout remains an ordinary refusal and
does not by itself determine whether an earlier invocation had exchanged files.

## Production and test boundaries

Production always requires the executor; it has no path/name/opt-out argument.
The test-only primitive retains an explicit opt-out for old inert swap fixtures,
which do not execute A. The journal integration test path explicitly requires
the executor and uses complete signed fixture applications.

Protected ancestors, local/private storage and no concurrent privileged writer
remain caller prerequisites. The namespace lease is cooperative; an admin/root
adversary is not made harmless by an inode comparison. This is not an installed
app receipt, a live-B proof, a permanent filesystem guarantee or activation.

Independent review found no additional blocker in descriptor cleanup, binding,
lock coverage, production/test separation or committed-state error handling.
Acceptance evidence is recorded separately in `vpn-executor-tests.md`.

## Still required

Create and launch the independently authenticated executor from an authorized
source; define its bounded cleanup/recovery. Then implement the writable
Applications destination contract and installed/live-B verification before
advancing the selector. No system installation or network change is performed
by this increment.

The subsequent provisioning increment now creates/resumes the exact protected
A copy atomically, but still does not launch or remove it. See
`vpn-executor-provisioning.md`.
