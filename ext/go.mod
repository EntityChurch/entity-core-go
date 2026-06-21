module go.entitychurch.org/entity-core-go/ext

go 1.25.0

require github.com/fxamacker/cbor/v2 v2.9.0

require (
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/grandcat/zeroconf v1.0.0 // indirect
	github.com/miekg/dns v1.1.27 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.entitychurch.org/entity-core-go/core v0.8.0
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
)

replace go.entitychurch.org/entity-core-go/core v0.8.0 => ../core
