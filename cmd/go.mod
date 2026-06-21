module go.entitychurch.org/entity-core-go/cmd

go 1.25.0

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/fxamacker/cbor/v2 v2.9.0
	github.com/mr-tron/base58 v1.2.0
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.entitychurch.org/entity-core-go/core v0.8.0
	go.entitychurch.org/entity-core-go/ext v0.8.0
	golang.org/x/crypto v0.30.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	modernc.org/libc v1.72.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.50.0 // indirect
)

replace go.entitychurch.org/entity-core-go/core v0.8.0 => ../core

replace go.entitychurch.org/entity-core-go/ext v0.8.0 => ../ext
