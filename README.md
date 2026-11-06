# bevy_network_stack

Patched Rust crates: the renet networking stack plus the Bevy helper
crates `moonshine_behavior`, `moonshine_kind`, `moonshine_util` and `bevy_capture`. Each
upstream project is pinned as a submodule, and its fixes are kept as a reviewable series
of patch mails. A generated branch per project holds the upstream history plus one commit
per patch, so Cargo can depend on it through a git `rev`.

## Layout

- `upstream/<crate>`: upstream repository as a submodule, pinned to the patched revision.
- `patches/<crate>/NNNN-<slug>.patch`: `git format-patch` mails, paths relative to the
  upstream repository root.
- `patches/<crate>/series`: patch file names, one per line, in apply order.
- `scripts/apply <crate>`: rebuilds branch `<crate>` from the pinned submodule and the
  series. Author, committer and dates come from each patch mail, so the same inputs give
  the same branch SHA. If a patch does not apply, it names the patch, exits non-zero and
  leaves the branch unchanged.
- `scripts/test <crate>`: runs the tests of the patched packages on a clean checkout of
  branch `<crate>`. When `<crate>` depends on another crate patched here (`moonshine_kind`
  on `moonshine-util`, `moonshine_behavior` on `moonshine-kind` and `moonshine-util`), the
  dependency resolves from a checkout of its generated branch through a cargo
  `[patch.crates-io]` config, so run `scripts/apply` for the dependencies first. Set
  `CARGO_TARGET_DIR`; it defaults to `target/` in this repository. Upstream renet and the
  moonshine crates commit no `Cargo.lock`, and the `bevy_capture` lock predates the Bevy
  0.20 port, so test dependencies resolve from crates.io on each run; a later failure can
  come from a new dependency release, not a patch.
- `scripts/lib/*.sh`: functions shared by both scripts, one file per domain and named
  `domain::function`: `cli`, `git`, `workspace`, `patch` and `crate`. They are sourced and
  have no side effects until `main` calls them.
- `<crate>` branches (`renet`, `moonshine_behavior`, `moonshine_kind`, `moonshine_util`,
  `bevy_capture`): generated output of `scripts/apply`. Never edit them by
  hand; change the patches and regenerate.

## Update flow

1. Bump the submodule: `git -C upstream/<crate> checkout <rev>`, then
   `git add upstream/<crate>`. A new crate is added with
   `git submodule add <url> upstream/<crate>`, a `patches/<crate>/series`, and its test
   packages and patched dependencies in `scripts/lib/crate.sh`.
2. Fix or refresh the patches: check out branch `<crate>` in a scratch worktree, rebase
   or edit its commits, then regenerate the mails with
   `git format-patch --zero-commit --no-signature --no-numbered -o patches/<crate> <base>..HEAD`
   and update `patches/<crate>/series`.
3. Run `scripts/apply <crate>`.
4. Run `scripts/test <crate>`, and `scripts/test` for every crate that depends on it. Do
   not continue until they pass.
5. Commit `main` and push `main` and the regenerated branches.
6. Bump the `rev` in the consuming project to the new branch SHAs.

## Patches

### renet

Upstream: <https://github.com/lucaspoffo/renet> at `ec43e8016eb9443e9d6e20729553bb850cdc7538`.

Rebased from `bc4a387b53faef4d1e7e80cf59ff682252994f89` (Release 2.0): `renetcode/` is
unchanged across that range, so all eight patches apply unchanged; none refreshed or dropped.
`renetcode/Cargo.toml` still says `version = "2.0.0"` at the new pin.

- `0001` R1: reject sequence widths above 8 before `read_sequence` can panic.
- `0002` R2: replay protection tracks the whole u64 range without overflow.
- `0003` D1: parse a packet before consuming its replay sequence.
- `0004` D6: accept 17-byte sequence-zero `Disconnect` and `ConnectionDenied` packets.
- `0005` D4: reject malformed connect-token server address lists instead of panicking.
- `0006` D5: saturate an inverted token lifetime and check the generated expiry.
- `0007` R1, D1, D4, D5, D6: regression tests and an adversarial datagram corpus for the
  decoder, client and tokens.
- `0008` D2, D3, D7, D8, D9: server liveness, challenge binding, nonce partition, single-use
  connect tokens and the Secure restart cutoff (`max_connect_token_lifetime`, an API break),
  with the server tests.

### moonshine_util

Upstream: <https://github.com/Zeenobit/moonshine_util> at `5358f9596f52072843bb15ac883693a8f7324f98`
(0.6.0).

- `0001`: `Expect<T>` takes `IS_READ_ONLY` from `T` instead of always claiming read-only
  access, so a mutable lens over `Query<Expect<&mut T>>` is allowed; with its test.

### moonshine_kind

Upstream: <https://github.com/Zeenobit/moonshine_kind> at `04573fe1fafeba19ee2c33cab40193c63b0d0217`
(0.6.0).

- `0001`: every `Instance<T>` query excludes resource entities (`Without<IsResource>`), so a
  kind whose filter only excludes components no longer matches the entities Bevy stores
  resources on; with its test.

Dropped from the earlier in-tree copy: the `InstanceMut` access change and its two
`instance_mut_conflicts_*` tests. Upstream fixed that access in `a4236d9`, which 0.6.0
contains.

### moonshine_behavior

Upstream: <https://github.com/Zeenobit/moonshine_behavior> at
`724a48c8b2119e57b1d360a3400329a4438ad811` (0.6.0). Tested against the generated
`moonshine_kind` and `moonshine_util` branches.

- `0001`: `BehaviorItem::ready()`, the inverse of `has_transition()`, for guards that must
  not override a queued transition.
- `0002`: `insert_restored()` inserts a saved behavior stack, and the replay of a restored
  stack skips `Behavior::filter_next`, so a state reached through states that have since
  stopped still loads; with its test.

Dropped from the earlier in-tree copy: the removal of upstream's deprecated items
(`TransitionSequence`, `TransitionChanged`, `BehaviorItem::index`). The consuming project does not use
them, and keeping them keeps the patch series small.

### bevy_capture

Upstream: <https://github.com/jannik4/bevy_capture> at `3439c61595ef40e07a54d9de34e0768fb1c1222b`
(v0.6.0, Bevy 0.19). Every encoder stays an optional upstream feature; the consuming project enables
`mp4_ffmpeg_cli_pipe`, which `scripts/test` builds.

- `0001`: port to Bevy 0.20: require bevy 0.20 with upstream's feature list, and handle the
  `Result` that wgpu 30's `get_mapped_range()` returns. The committed `Cargo.lock` still
  resolves Bevy 0.19; cargo re-resolves it on each test run.
- `0002`: size the readback buffer rows by aligning `width * 4` bytes, as the copy and
  un-pad steps do, so widths that are a multiple of 64 but not 256 no longer produce
  over-long frames.
- `0003`: runtime test in `tests/readback.rs` that captures a 320 by 2 headless target through
  `CapturePlugin` and asserts the frame byte length and both rows; it needs a GPU adapter.

## License

Upstream renet is dual-licensed under MIT and Apache-2.0; see `LICENSE-MIT` and
`LICENSE-APACHE`. The patches and scripts in this repository are under the same terms.
Upstream bevy_capture is under MIT or Apache-2.0, and upstream moonshine_behavior,
moonshine_kind and moonshine_util are under MIT; see the `LICENSE` files in their
submodules.
