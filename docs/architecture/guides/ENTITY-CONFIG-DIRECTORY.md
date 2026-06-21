# ~/.entity/ Configuration Directory

The `~/.entity/` directory stores persistent identities and peer configurations. This convention was established by the Rust CLI and is shared across implementations.

## Directory Layout

```
~/.entity/
├── identities/                    # Named identities (keypairs)
│   ├── framework-admin            # PEM private key (mode 0600)
│   ├── framework-admin.pub        # PEM public key
│   ├── framework-admin.json       # Metadata sidecar (peer_id, key_type)
│   ├── default
│   ├── default.pub
│   └── default.json
└── peers/                         # Named peer instances
    └── workstation/
        ├── keypair                # PEM private key (mode 0600)
        ├── keypair.pub            # PEM public key
        ├── keypair.json           # Metadata sidecar
        ├── config.toml            # Peer configuration
        └── grants.toml            # Access control grants
```

## Key File Format

Private keys use a PEM-like format wrapping a base64-encoded 32-byte Ed25519 seed:

```
-----BEGIN ENTITY PRIVATE KEY-----
<base64 encoded 32-byte seed>
-----END ENTITY PRIVATE KEY-----
```

The peer ID is derived from the public key: `Base58(0x01 || 0x01 || SHA256(pubkey))`.

## grants.toml

Defines named groups of peers and their access levels:

```toml
[groups.admin]
resources = ["*"]
operations = ["*"]
description = "Full access to all resources"
members = ["2KS7wDt4QQhFph3BrGbrwrgtx28DkphxsbbWSVCea5JnPt"]

[groups.readers]
resources = ["system/type/*"]
operations = ["get"]
description = "Read-only access to types"
members = ["2ABC123..."]
```

### Grant Resolution

When a remote peer connects and authenticates, grants are resolved in order:

1. **Grant resolver** (from grants.toml): checks if the remote peer ID is a member of any group
   - `admin` group: full wildcard grants (`*` handlers, `*` resources, `*` operations)
   - Other groups: scoped to the group's resources and operations
2. **Static connection grants** (if set via `WithConnectionGrants`): used for all peers
3. **Default connection grants**: read-only access to types and handler manifests

Unknown peers (not in any group) fall through to step 2 or 3.

## config.toml

Peer configuration. The Go peer currently uses only `listen_addr`:

```toml
[peer]
listen_addr = "127.0.0.1:9000"
```

Other fields (storage, handlers, capabilities, logging) are defined by the Rust implementation and are silently ignored by the Go peer.

## CLI Usage

```bash
# Named peer: persistent identity + grants
entity-peer --name workstation

# Named peer with address override
entity-peer --name workstation --addr :9005

# Ephemeral peer (no persistence)
entity-peer --addr :9002
```
