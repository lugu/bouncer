package bouncer

import (
	"fmt"

	"github.com/lugu/qiloop"
	"github.com/lugu/qiloop/bus"
	"github.com/lugu/qiloop/bus/directory"
)

// NewWatcher duplicates entry from one servvice directory to another
func NewWatcher(toWatch, toUpdate bus.Session) {
}

// Firewall create a firewall which connect to internalURL and expose
// it at externalURL. It uses user, token to authenticate the incomming
// connections.
func Firewall(internalURL, internalUser, internalToken,
	externalURL, externalUser, externalToken string) (bus.Server, error) {

	// 1. access the internal directory
	internalSession, err := qiloop.NewSession(internalURL,
		internalUser, internalToken)
	if err != nil {
		return nil, fmt.Errorf("internal session: %s", err)
	}

	var auth bus.Authenticator = bus.Yes{}
	if externalUser != "" {
		passwords := map[string]string{
			externalUser: externalToken,
		}
		auth = bus.Dictionary(passwords)
	}
	// 2. start an external directory
	server, err := directory.NewServer(externalURL, auth)
	if err != nil {
		return nil, fmt.Errorf("external directory: %s", err)
	}
	externalSession := server.Session()

	// 3. import services from the internal directory
	NewWatcher(externalSession, internalSession)

	// 4. propagate service from the external directory
	NewWatcher(externalSession, internalSession)

	return server, nil
}
