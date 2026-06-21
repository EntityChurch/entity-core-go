// Package peer implements the Peer lifecycle, builder, connections, and
// sessions.
//
// A Peer is the top-level construct that ties together identity, handlers,
// storage, and network connections. Use the functional options builder
// pattern to configure:
//
//	peer, err := peer.New(
//	    peer.WithIdentity(keypair),
//	    peer.WithListenAddr("127.0.0.1:9000"),
//	    peer.WithHandler("local/files/*", filesHandler),
//	)
//
// Dependencies: all other packages
package peer
