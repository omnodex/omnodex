# Signed evidence chain

Omnodex can prove that its record of what an agent did has not been edited
since it was written, without asking you to trust Omnodex. Events are hashed
into a chain, each link of the chain is signed with a key that stays on your
machine, and an open verifier checks a bundle of events and links.

```bash
omnodex seal                                   # seal what is new (the background pass does this too)
omnodex seal key                               # print this machine's key id and public key
omnodex export --bundle --out evidence.jsonl --since 30d
omnodex verify evidence.jsonl --key <key id or public key>
```

## What it proves, and what it does not

- Events inside a bundle were not edited, dropped, added or reordered after
  they were sealed, and each seal was signed by the key named in it.
- With `--key`, the signing key is one you chose to trust. Without it,
  `verify` only shows the bundle is consistent with the keys it carries; the
  person who made the bundle could have made it with any key.
- Events recorded after the last seal are not covered until the next seal.
  `export --bundle` seals first, so a fresh bundle has no such gap.
- Someone with control of the machine can delete the log and the key, or
  rewrite history and sign it with the same key. Nothing here prevents
  that. Capture pauses and monitoring changes are events in the chain, so a
  bundle shows when recording was off.
- A bundle holds every event in full, prompts and tool parameters included.

## Seals

The background pass (and `omnodex seal`) is the only thing that seals. Hooks
write events as before, with no extra work. Each seal covers every event
recorded since the previous one, in this order: by `recorded_at`, then by
session file name, then by position in the file.

Seals are kept in `event-log/seals.jsonl`, one JSON object per line, beside
the session files and not in them. The signing key is
`signing/seal-key.json` in the Omnodex home (an Ed25519 key, created on the
first seal); its public half is printed by `omnodex seal key`.

### Hashing

1. The **canonical form** of an event is its JSON as read from the log,
   serialized by [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JSON
   Canonicalization Scheme): keys sorted by UTF-16 code unit, no whitespace,
   strings and numbers as ECMAScript serializes them.
2. The **event hash** is SHA-256 of the canonical form encoded as UTF-8,
   written as 64 lowercase hex digits.
3. The **head** starts at the genesis head, 64 zeros, and is folded forward
   for each event in the seal's order: `head = SHA-256(previous head bytes ||
   event hash bytes)`, where each operand is its 32 raw bytes (the hex
   decoded). The head of one seal is the previous head of the next.

### Seal fields

| Field | Meaning |
| --- | --- |
| `format` | `omnodex.seal/1` |
| `seq` | 1 for a machine's first seal, then +1 |
| `sealed_at` | When it was made (ISO 8601) |
| `prev_head`, `head` | The head before and after this seal's events |
| `count`, `event_ids` | The sealed events, in folding order |
| `first_recorded_at`, `last_recorded_at` | `recorded_at` of the first and last event |
| `key_id`, `alg` | The signing key's id and `Ed25519` |
| `signature` | Hex Ed25519 signature (see below) |
| `local` | Reading state used by the sealer. Not signed, and not in bundles. |

The **signature** is Ed25519 over the UTF-8 canonical form (RFC 8785) of the
seal object without `signature` (and without `local` and the bundle's `type`
tag). The **key id** is the first 16 hex digits of SHA-256 over the raw
32-byte public key. A raw public key becomes a DER SPKI key by prefixing the
bytes `302a300506032b6570032100`.

## Bundle format (`omnodex.bundle/1`)

A bundle is a UTF-8 file with one JSON object per line. The `type` field says
which kind:

| `type` | Fields | Notes |
| --- | --- | --- |
| `manifest` | `format` (`omnodex.bundle/1`), `created_at`, `range` (`since`, `until`, each a time or null), `first_seal`, `last_seal`, `seals`, `events` | First line |
| `key` | `key_id`, `alg`, `public_key` (raw, hex) | One per signing key used |
| `seal` | The seal fields above, plus `type` | In `seq` order |
| `event` | `seal` (the seq it belongs to), `event_hash`, `event` (the logged event) | After its seal, in the seal's order |

A range selects whole seals: every seal with events inside the range is
included, so a bundle can run wider than the range asked for. A bundle may
start at any seal; it does not need to start at seal 1.

## Verifying (what `omnodex verify` does)

For each seal, in order:

| # | Check | Problem code |
| --- | --- | --- |
| 1 | The key named by `key_id` is in the bundle | `unknown_key` |
| 2 | The signature is valid for that key | `bad_signature` |
| 3 | If you pass `--key`, the key is one you trust | `key_untrusted` |
| 4 | `seq` follows the previous seal, and `prev_head` equals its `head` | `gap`, `chain_break` |
| 5 | `count` equals the number of `event_ids` | `count_mismatch` |
| 6 | Every id in `event_ids` has an event line under this seal | `dropped` |
| 7 | No event line is under this seal that its `event_ids` do not list | `extra` |
| 8 | The event lines are in the order of `event_ids` | `reordered` |
| 9 | Each event's recomputed hash equals its `event_hash` | `edited` (names the event) |
| 10 | Folding the recomputed hashes in `event_ids` order from `prev_head` gives `head` | `edited` |

`omnodex verify` also lists the capture pauses and monitoring changes inside the
bundle (`capture.paused`, `capture.resumed`, `monitoring.changed`,
`monitoring.unexplained_change`), so a reader sees when recording was off.
It exits 0 for a valid bundle, 2 when it finds a problem, and 1 when it cannot
run. `--json` prints the full report.

The checks in `packages/cli/src/evidence/verify.ts` and the arithmetic in
`canonical.ts` have no dependencies beyond Node's `crypto`; they can be read
as a reference when writing another verifier.
