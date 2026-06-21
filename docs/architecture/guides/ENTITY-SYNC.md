# entity-sync

Set up automatic tree prefix synchronization between two peers.

## Quick Start

```bash
# One-way: sync local/files/ from peer A to peer B
go run ./cmd/entity-sync \
  -from 127.0.0.1:9001 \
  -to 127.0.0.1:9002 \
  -source-prefix local/files/

# Bidirectional: both peers stay in sync
go run ./cmd/entity-sync \
  -from 127.0.0.1:9001 \
  -to 127.0.0.1:9002 \
  -source-prefix local/files/ \
  -bidirectional

# Different destination prefix
go run ./cmd/entity-sync \
  -from 127.0.0.1:9001 \
  -to 127.0.0.1:9002 \
  -source-prefix local/files/ \
  -dest-prefix mirror/files/

# List active sync chains on a peer
go run ./cmd/entity-sync list 127.0.0.1:9002
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-from` | (required) | Source peer address (`host:port`) |
| `-to` | (required) | Destination peer address (`host:port`) |
| `-source-prefix` | (required) | Tree prefix to watch on source (must end with `/`) |
| `-dest-prefix` | source-prefix | Destination prefix (defaults to same as source) |
| `-strategy` | `source-wins` | Merge strategy: `source-wins`, `target-wins`, `no-overwrite` |
| `-identity` | (ephemeral) | Named identity from `~/.entity/identities/` |
| `-bidirectional` | false | Set up sync in both directions |
| `-ttl` | `24h` | Delivery token lifetime (e.g., `1h`, `168h` for 7 days) |

## How It Works

entity-sync creates a continuation chain on the destination peer:

```
Source peer (A)                    Destination peer (B)
  subscription ─────────────────►  inbox/sync/{prefix}/extract
    pattern: {prefix}/*               └─ continuation: extract from A
    on change: notify B                    └─ delivers to ──────────►  inbox/sync/{prefix}/merge
                                                                          └─ continuation: merge locally
                                                                               target: system/tree
                                                                               params: source_envelope, strategy, prefixes
```

1. A **subscription** on the source peer watches for changes under the prefix
2. When something changes, a notification is delivered to the destination peer's **extract continuation**
3. The extract continuation calls `tree extract` on the source peer to get the current snapshot
4. The extract result (envelope with trie nodes + entities) is delivered to the **merge continuation**
5. The merge continuation calls `tree merge` locally with `source_envelope`, writing entities to the destination prefix

## Token Expiration

The delivery token used for subscription notifications has a TTL (default: 24 hours). After it expires, notifications can no longer be delivered and sync stops silently.

**To renew**: re-run the same `entity-sync` command. The subscription handler deduplicates based on (subscriber, pattern, deliver_uri), so the existing subscription is updated with a fresh token.

```bash
# Renew with 7-day TTL
go run ./cmd/entity-sync \
  -from 127.0.0.1:9001 \
  -to 127.0.0.1:9002 \
  -source-prefix local/files/ \
  -ttl 168h
```

## Listing Active Sync Chains

```bash
$ go run ./cmd/entity-sync list 127.0.0.1:9002

Sync chains on 127.0.0.1:9002 (2KPn...):

  local/files/
    extract → entity://2KYM.../system/tree (extract)
             prefix: local/files/
             delivers to: entity://2KPn.../system/inbox/sync/local/files/merge
    merge   → system/tree (merge)
             prefix: local/files/
```

## Merge Strategies

| Strategy | Behavior |
|----------|----------|
| `source-wins` | Overwrites destination on conflict (default) |
| `target-wins` | Keeps destination version on conflict |
| `no-overwrite` | Only writes new paths, skips existing |

## With peer-manager

```bash
# Start two peers
go run ./cmd/peer-manager start --name desktop --type go --debug
go run ./cmd/peer-manager start --name laptop --type go --debug

# Get addresses
DESKTOP=$(go run ./cmd/peer-manager addr desktop)
LAPTOP=$(go run ./cmd/peer-manager addr laptop)

# Bidirectional file sync
go run ./cmd/entity-sync \
  -from $DESKTOP -to $LAPTOP \
  -source-prefix local/files/ \
  -bidirectional \
  -identity framework-admin \
  -ttl 168h
```

## Cross-Implementation Sync

Works between any combination of Go, Rust, and Python peers:

```bash
# Python → Go sync
go run ./cmd/entity-sync \
  -from 127.0.0.1:9001 \  # Python peer
  -to 127.0.0.1:9002 \    # Go peer
  -source-prefix system/validate/ \
  -identity framework-admin
```

## Limitations

- **Token expiration**: Sync stops when the delivery token expires. Re-run to renew.
- **No deletion propagation**: Merge is additive — deleting entities on source doesn't delete on destination.
- **No initial sync**: Only changes after setup are propagated. Use `tree extract` + `tree merge` manually for initial sync.
- **Single prefix**: Each command syncs one prefix. Run multiple times for multiple prefixes.
