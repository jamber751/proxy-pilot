# VPN one-click update broker

Status: design boundary for the next implementation stage. The broker is not a
general privileged helper and Sparkle is never a root authority.

## User flow

1. The ordinary updater discovers and downloads an update.
2. If VPN support is absent, the existing isolated Sparkle flow installs it.
3. If VPN support is installed, the updater asks the already-installed broker to
   verify one local candidate. macOS may show the normal authorization UI only
   when the broker itself is first installed or replaced.
4. The broker reports only `checking`, `ready`, `installing`, `complete`, or
   `failed`. The app keeps the current VPN usable until protected recovery is
   armed and the signed A→B transition is ready.
5. Existing journal, executor, readiness, recovery, and cleanup code performs the
   replacement. A crash or reboot resumes from the protected journal.

## Fixed authority surface

The broker has only two operations:

- `submit(expectedFromSequence, candidateDirectoryDescriptor)`
- `status()`

The request does not contain a URL, filesystem path, command, arguments, shell,
environment, owner UID, destination, bundle identifier, signing key, transaction
ID, or Sparkle token. The directory arrives as an already-open descriptor; the
broker rejects non-directories, links, unsafe ownership/modes, and unexpected
entries before reading payload bytes.

`status()` returns a bounded enum and non-sensitive numeric sequence/revision. It
never returns paths, usernames, payloads, signatures, logs, or error descriptions.

## Trust and copy boundary

The submitted directory is untrusted and remains ordinary-user-owned. Before any
VPN or application mutation, the broker:

1. opens only the fixed package layout relative to the descriptor;
2. checks size, type, owner, mode, link count, and canonical filenames;
3. copies each exact regular file into a new root-private inbox without following
   links or overwriting an existing transaction;
4. fsyncs the files, inbox, and parent;
5. verifies the release authority, full signed A→B edge, application A/B pins,
   helper pins, engine manifest/artifacts, versions, protocol, and current durable
   selector;
6. revalidates the private copy immediately before handing it to the existing
   joint-update preparation pipeline.

Nothing is executed from the submitted directory. A failed or stale submission
does not stop VPN, alter the selector, spend the activation budget, or modify the
installed application.

The current inbox foundation publishes under a SHA-256 content-derived name. It
clones only the nine fixed direct children, bounds recursive entries/bytes/depth,
re-snapshots the mutable source before publication, synchronizes the copied tree,
and atomically renames a private pending directory. An identical retry resumes or
returns the same inbox; another candidate, a changed published inbox, or another
pending identity is refused without overwrite. This copier is not yet reachable
from an endpoint and does not call the mutation pipeline.

The transport foundation now accepts one fixed binary request per authenticated
local Unix connection. The live kernel peer is checked before parsing the frame;
`submit` requires exactly one `SCM_RIGHTS` directory descriptor and `status`
requires none. Malformed, appended, truncated, timed-out, or descriptor-bearing
status requests are refused, and every received descriptor is close-on-exec and
closed on all refusal and completion paths. The fixed `update-broker.sock`
endpoint is private (`0600`) inside an already-open trusted directory. This
transport is still not registered with launchd and cannot invoke the inbox or
mutation pipeline.

## Broker lifecycle

The broker is a separate root process and endpoint, not the selected VPN helper
listener. Its executable and launchd description use fixed protected locations.
The first production release must choose and test one explicit rotation rule:

- a dedicated broker identity pinned by the installed package and rotated by a
  separately signed broker transition; or
- a broker role bound to release A that authorizes and installs exact broker B as
  part of the same A→B transaction.

No release may mix these models implicitly. Uninstall removes only the exact
broker label, endpoint, executable receipt, and private inboxes proven to belong
to ProxyPilot.

## Required acceptance gates

- malformed, oversized, linked, mutable, stale, downgraded, or wrong-key input
  has zero namespace/runtime effects;
- unrelated signed releases and valid B without the exact A→B edge are refused;
- duplicate submit is idempotent, while a different concurrent candidate is busy;
- caller death and broker restart preserve either no transaction or one resumable
  root-private transaction;
- crash/reboot tests cover every copy, journal, drain, exchange, selection,
  readiness, retirement, and cleanup checkpoint;
- native acceptance passes on Apple Silicon and Intel/macOS 11 before release.
