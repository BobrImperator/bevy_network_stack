# bevy_network_stack

Patched networking crates. Each upstream project is pinned as a
submodule, and its fixes are kept as a reviewable series of patch mails. A generated
branch per project holds the upstream history plus one commit per patch, so Cargo can
depend on it through a git `rev`.

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
  branch `<crate>`. Set `CARGO_TARGET_DIR`; it defaults to `target/` in this repository.
  Upstream renet commits no `Cargo.lock`, so test dependencies resolve from crates.io on
  each run; a later failure can come from a new dependency release, not a patch.
- `scripts/lib/*.sh`: functions shared by both scripts, one file per domain and named
  `domain::function`: `cli`, `git`, `workspace`, `patch` and `crate`. They are sourced and
  have no side effects until `main` calls them.
- `<crate>` branches (`renet`): generated output of `scripts/apply`. Never edit them by
  hand; change the patches and regenerate.

## Update flow

1. Bump the submodule: `git -C upstream/<crate> checkout <rev>`, then
   `git add upstream/<crate>`.
2. Fix or refresh the patches: check out branch `<crate>` in a scratch worktree, rebase
   or edit its commits, then regenerate the mails with
   `git format-patch --zero-commit --no-signature --no-numbered -o patches/<crate> <base>..HEAD`
   and update `patches/<crate>/series`.
3. Run `scripts/apply <crate>`.
4. Run `scripts/test <crate>`. Do not continue until it passes.
5. Commit `main` and push `main` and the `<crate>` branch.
6. Bump the `rev` in the consuming project to the new `<crate>` branch SHA.

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

## License

Upstream renet is dual-licensed under MIT and Apache-2.0; see `LICENSE-MIT` and
`LICENSE-APACHE`. The patches and scripts in this repository are under the same terms.
