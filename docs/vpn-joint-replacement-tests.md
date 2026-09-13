# Joint application replacement integration tests

This boundary is tested with disposable protected service and application
directories, real signed universal A/B application bundles, a signed inert
universal helper artifact, canonical manifests and an exact transition signed by
a deterministic fixture-only Ed25519 key. The executing A binary remains outside
both swap slots while its byte-identical signed application copy occupies the
current slot.

The runtime is a local fake that records drain and can inject drain failure,
lease loss, or journal corruption. It never contacts launchd, starts a helper,
installs an application, changes a profile, or performs network/Keychain work.

Cases cover successful exchange and B/A retry; exact UUID, revision,
phase, selected-release and process-policy refusals before runtime construction
or namespace effects; invalid B before drain; failed drain; post-drain lease or
journal changes; and preservation of selector, journal phase/revision, activation
budget and manual-off intent. Results distinguish namespace replacement
from selector advancement, runtime readiness, and installed/live application
proof.

The implemented suite uses complete signed application bundles as the external
A, B and updater executors; copying only a Mach-O out of its signed bundle would
invalidate the resource-bound static-code context and is deliberately avoided.
It asserts exact controlled error exits rather than accepting harness crashes.
The five test groups cover successful exchange, exact B/A retry and a failed
retry remaining forward; preserved selector, pending journal and manual-off
budget; stale UUID/revision and invalid phase/selection; B and updater process
denial before the runtime factory; corrupt B before drain; drain failure; lease,
journal and bundle mutation after drain; service and namespace lock contention;
and the production non-root guard. A start marker proves the fake runtime's start
method is never invoked.

On 13 September 2026 the final discovery-form targeted suite passed **5 tests in
21.101 seconds**
using disposable directories, a fixture-only signing key, ad-hoc signed
Universal applications/helper, and a fake drain runtime. No launchd, root,
installed application, helper execution, profile, network, Keychain, or
production signing material was used. These tests prove the bounded protected
copy transaction and local fixture-process authentication, not `/Applications`
replacement, production installed/live-B identity, VPN
readiness, journal phase advancement, selector advancement, or physical
power-loss durability.

An independent final discovery run by the integrating agent also passed all
**5 tests in 21.843 seconds** with no skips.
