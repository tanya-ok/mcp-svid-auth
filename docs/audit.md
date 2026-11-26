# Audit integrity and completeness

Each authz and tool decision is one JSON record with a random ID, previous ID and SHA-256 hash of the previous canonical record; the format is the [audit event contract](architecture/contracts/audit-event.md). There is one writer per file, enforced by an exclusive lock on `<file>.lock`, and each record names its `replica_id` and is fsynced. Resuming validates the links in the last 1 MiB of the file and refuses a broken chain or an unterminated last line; `mcp-svid-audit-verify` checks the whole file. The verifier checks the record schema, links, duplicate IDs and timestamp order without echoing malformed record contents.

## What a check proves

| Verification | Detects | Does not prove |
|---|---|---|
| Internal links only | Edited linked records, middle deletion, head deletion, reordering and malformed records | Last-record edits, suffix deletion, or a consistently rebuilt chain |
| Links plus a separately trusted terminal checkpoint | Those attacks plus changed terminal record, suffix deletion, or chain replacement up to the checkpoint | Events never logged, events after the checkpoint, a dishonest writer, or a checkpoint the attacker can also replace |
| Links plus a signed checkpoint verified with `--checkpoint-public-key` | Those attacks plus a replaced or rebuilt checkpoint, wherever it is stored | An older genuine checkpoint presented with a log truncated to it; events never logged, events after the checkpoint, a dishonest writer, or a stolen checkpoint signing key |
| Signed checkpoint plus a high-water mark (`--min-sequence`, `--min-records`, `--max-age`) | Those attacks plus a stale genuine checkpoint with a truncated log | Events never logged, a dishonest writer, a stolen signing key, or a high-water mark kept where the attacker can change it |

An unsigned checkpoint (version 1) contains the format version, record count, last record ID and last record hash. Its security comes from independently protected storage and a trusted capture process.

A signed checkpoint (version 2) adds `key_id`, `sequence` (1 for the first, then the previous sequence plus one), `created_at` and `previous` (SHA-256 of the previous signed checkpoint's signed fields), and an Ed25519 `signature` over the domain-separated JCS form of all of them. The signing key belongs to the operator who captures checkpoints; the authz and MCP processes never need it. Only the public key is required to verify, so the checkpoint itself may live beside the log, but the latest sequence or record count must be kept elsewhere to detect a stale checkpoint.

## Capture and verify

After ending an observation period, capture its complete log and create a new checkpoint:

```sh
mcp-svid-audit-verify notes-a.jsonl --write-checkpoint notes-a.checkpoint.json
```

The command refuses an invalid chain and never overwrites an existing checkpoint. Put the checkpoint under a separate operator's control, for example an offline retained copy or storage where the workload has no write access. Creating it beside the log is useful for a demo but supplies no independent trust.

To sign it, create an Ed25519 key outside the workload, for example `openssl genpkey -algorithm ed25519 -out checkpoint.key`, `chmod 600 checkpoint.key` and `openssl pkey -in checkpoint.key -pubout -out checkpoint.pub`, then add `--signing-key checkpoint.key` to the command above, and `--previous-checkpoint last.cp` for every checkpoint after the first. The previous checkpoint must be signed by the same key and its terminal record must appear at its position in the log. Verification with `--checkpoint-public-key checkpoint.pub` refuses an unsigned checkpoint, one signed by another key, and any change to its fields.

Verify the exact captured log against that retained baseline:

```sh
mcp-svid-audit-verify notes-a.jsonl --checkpoint /trusted/notes-a.checkpoint.json
mcp-svid-audit-verify notes-a.jsonl --checkpoint notes-a.checkpoint.json --checkpoint-public-key checkpoint.pub
```

Without `--checkpoint-public-key` a signed checkpoint is compared by terminal state only, exactly like an unsigned one. Add `--min-sequence N` (the last sequence you recorded), `--min-records N` or `--max-age SECONDS` to refuse an older genuine checkpoint presented with a truncated log.

This compares the exact terminal state. A log with additional records also differs: freeze the captured interval or establish a new trusted checkpoint for the new interval. Never regenerate a baseline from a suspect log to make verification pass.

Without a checkpoint, use:

```sh
mcp-svid-audit-verify authz.jsonl notes-a.jsonl
```

An `intact` result then means internal consistency only. Each file is a separate chain. Stderr logs start a new chain on every process restart; use one capture per process, or configure a persistent file with exactly one writer.

## Rotation

1. Rename the log file, for example `notes-a.jsonl` to `notes-a.1.jsonl`. The running writer continues in a new `notes-a.jsonl` whose first record links to the last record of the renamed file.
2. Checkpoint the renamed file: `mcp-svid-audit-verify notes-a.1.jsonl --write-checkpoint notes-a.1.cp --signing-key checkpoint.key --previous-checkpoint <last>`.
3. Verify the current file against it: `mcp-svid-audit-verify notes-a.jsonl --continues-from notes-a.1.cp --checkpoint-public-key checkpoint.pub`.

A restarted writer resumes the existing file. Do not rename while the writer is stopped and then start it on an empty file: it would start a new chain with a genesis record, which `--continues-from` reports as broken.

## Safe diagnostics

Client errors are fixed strings. Audit reasons contain fixed descriptions or exception class names, never exception messages. Unverified subjects are recorded as `unverified:sha256:<digest prefix>`; JWT-SVID IDs are correlated using `svid_jti_sha256=<digest prefix>`, without retaining arbitrary claim text. Issued access token `jti` values are written in clear in authz allow records so they can be revoked; they are identifiers, not credentials. Unknown tool names are not echoed into the audit. No access token, assertion or private key belongs in a report.

The live demo saves the notes-a and notes-b chains and checkpoints in ignored `deploy/.data/`, then proves that deleting the last record fails against the captured checkpoint. These colocated checkpoints are demonstration artifacts, not a trusted archival system.
