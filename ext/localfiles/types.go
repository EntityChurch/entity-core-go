// Package localfiles implements the local/files domain handler per DOMAIN-LOCAL-FILES.md v1.0.
//
// The handler maps a host filesystem subtree into the entity tree, enabling
// file sync through the entity protocol. Files become entities; directories
// become listings. Content is stored inline as strings (prototype — size limited
// to ~10MB per file).
package localfiles

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"

	"github.com/fxamacker/cbor/v2"
)

// Type constants for the local files domain.
const (
	TypeFile           = "local/files/file"
	TypeDirectory      = "local/files/directory"
	TypeDirectoryEntry = "local/files/directory/entry"
	TypeDeleted        = "local/files/deleted"
	TypeRootConfig     = "local/files/root-config"
	TypeWatcherConfig  = "local/files/watcher-config"
	TypeWriteRequest   = "local/files/write-request"
	TypeWatchRequest   = "local/files/watch-request"
)

// FileData represents a file entity (v1.2 §5.1). Content is now a
// system/hash pointing at a system/content/blob; bytes flow through the
// shared CONTENT v3.6 substrate (FastCDC chunked, byte-identical across
// handlers and implementations).
type FileData struct {
	Path       string    `cbor:"path"`
	Size       uint64    `cbor:"size"`
	ModifiedAt *uint64   `cbor:"modified_at,omitempty"`
	Content    hash.Hash `cbor:"content"`
	MediaType  *string   `cbor:"media_type,omitempty"`
	Written    bool      `cbor:"written,omitempty"`
}

func (d FileData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeFile, cbor.RawMessage(raw))
}

func FileDataFromEntity(e entity.Entity) (FileData, error) {
	var d FileData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return FileData{}, err
	}
	return d, nil
}

// DirectoryData represents a directory listing (§2.3).
type DirectoryData struct {
	Path       string               `cbor:"path"`
	Children   []DirectoryEntryData `cbor:"children,omitempty"`
	ModifiedAt *uint64              `cbor:"modified_at,omitempty"`
}

func (d DirectoryData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDirectory, cbor.RawMessage(raw))
}

func DirectoryDataFromEntity(e entity.Entity) (DirectoryData, error) {
	var d DirectoryData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return DirectoryData{}, err
	}
	return d, nil
}

// DirectoryEntryData represents an entry within a directory listing (§2.4).
type DirectoryEntryData struct {
	Name       string  `cbor:"name"`
	EntityPath string  `cbor:"entity_path"`
	EntryType  string  `cbor:"entry_type"`
	Size       *uint64 `cbor:"size,omitempty"`
	ModifiedAt *uint64 `cbor:"modified_at,omitempty"`
}

// DeletedData represents a deletion confirmation (§2.5).
type DeletedData struct {
	Path    string `cbor:"path"`
	Existed bool   `cbor:"existed"`
}

func (d DeletedData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeDeleted, cbor.RawMessage(raw))
}

// RootConfigData represents a root mapping configuration (§2.6).
//
// Include + Exclude are filename glob patterns (filepath.Match). Both
// apply to files; Exclude additionally applies to directories
// (matched directories are skipped entirely, pruning their subtree).
// Include never applies to directories — otherwise a "*.md" filter
// would refuse to descend into subdirs.
//
// Semantics when both are set: a file is admitted iff it does NOT
// match Exclude AND (Include is empty OR it matches Include). Empty
// Include = no positive filter (all non-excluded files admitted).
type RootConfigData struct {
	Prefix             string   `cbor:"prefix"`
	FilesystemRoot     string   `cbor:"filesystem_root"`
	ReadOnly           bool     `cbor:"read_only,omitempty"`
	Exclude            []string `cbor:"exclude,omitempty"`
	Include            []string `cbor:"include,omitempty"`
	PublishDescriptors bool     `cbor:"publish_descriptors,omitempty"`
}

func (d RootConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeRootConfig, cbor.RawMessage(raw))
}

func RootConfigDataFromEntity(e entity.Entity) (RootConfigData, error) {
	var d RootConfigData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return RootConfigData{}, err
	}
	return d, nil
}

// WatcherConfigData represents file watcher state (§2.7).
type WatcherConfigData struct {
	RootName     string  `cbor:"root_name"`
	Status       string  `cbor:"status"`
	DebounceMs   *uint64 `cbor:"debounce_ms,omitempty"`
	ErrorMessage string  `cbor:"error_message,omitempty"`
}

func (d WatcherConfigData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeWatcherConfig, cbor.RawMessage(raw))
}

// WriteRequestData represents write operation parameters (v1.2 §5.4).
//
// Exactly one of Bytes / Content MUST be present. Bytes is the raw
// payload mode (handler chunks via FastCDC). Content is the dedup mode:
// the peer already has the blob from sync or another handler; the file
// is written by reference without re-transfer.
type WriteRequestData struct {
	Bytes      []byte     `cbor:"bytes,omitempty"`
	Content    *hash.Hash `cbor:"content,omitempty"`
	MediaType  *string    `cbor:"media_type,omitempty"`
	CreateDirs bool       `cbor:"create_dirs,omitempty"`
}

func (d WriteRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeWriteRequest, cbor.RawMessage(raw))
}

func WriteRequestDataFromEntity(e entity.Entity) (WriteRequestData, error) {
	var d WriteRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return WriteRequestData{}, err
	}
	return d, nil
}

// WatchRequestData represents watch operation parameters (§3.3).
type WatchRequestData struct {
	RootName   string  `cbor:"root_name"`
	Action     string  `cbor:"action,omitempty"`
	DebounceMs *uint64 `cbor:"debounce_ms,omitempty"`
}

func (d WatchRequestData) ToEntity() (entity.Entity, error) {
	raw, err := ecf.Encode(d)
	if err != nil {
		return entity.Entity{}, err
	}
	return entity.NewEntity(TypeWatchRequest, cbor.RawMessage(raw))
}

func WatchRequestDataFromEntity(e entity.Entity) (WatchRequestData, error) {
	var d WatchRequestData
	if err := ecf.Decode(e.Data, &d); err != nil {
		return WatchRequestData{}, err
	}
	return d, nil
}
