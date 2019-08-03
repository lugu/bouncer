// Package bouncer explores the challenges of implementing a gateway
// for QiMessaging.
//
// Limitations:
// 	- does not forward the capability map
// 	- authentication not based on PAM
//	- does not handle service info updates
//
// Missing in qiloop:
//	- SD shall unregister the service on disconnection
//	- service terminates when it loose its connection to SD
//	- SD could try to satisfy the service id during register
//
// Algorithm:
// 	0. Open a socket
// 	1. Listen for incoming messages
// 	2. Register to the directory
// 	3. For each incoming connection:
// 	3.1 Create a new Authenticator
// 	3.2 Create a new ServiceAuthenticate
// 	4 For each message:
// 	4.1 If the Authenticator is happy:
// 	4.1.1 Establish a new connection if necessary
// 	4.1.1 Forward the message
// 	4.2 If the Authenticator is not happy:
// 	4.1.1 Forward the message to the ServiceAuthenticate
// 	5. When the connection closes, close the remote connection
//
package bouncer

import (
	"fmt"
	"log"

	"github.com/lugu/qiloop"
	"github.com/lugu/qiloop/bus"
	"github.com/lugu/qiloop/bus/directory"
	"github.com/lugu/qiloop/bus/net"
	"github.com/lugu/qiloop/bus/services"
	"github.com/lugu/qiloop/bus/util"
)

type connection struct {
	endpoint net.EndPoint
	handler  int
	ghost    *ghostService
	target   net.EndPoint
}

func newConnection(ghost *ghostService, stream net.Stream,
	errors chan error, terminate chan struct{}) (*connection, error) {

	endpoint, err := net.DialEndPoint(ghost.info.Endpoints[0])
	// endpoint, err := bus.SelectEndPoint(ghost.info.Endpoints,
	// 	ghost.user, ghost.token)
	if err != nil {
		return nil, fmt.Errorf("ghost (%s): %s", ghost.info.Name, err)
	}

	conn := &connection{
		endpoint: net.NewEndPoint(stream),
		ghost:    ghost,
		target:   endpoint,
	}

	filter := func(hdr *net.Header) (matched bool, keep bool) {
		return true, true
	}
	consumer := func(msg *net.Message) error {
		return endpoint.Send(*msg)
	}
	closer := func(err error) {
		endpoint.Close()
	}
	conn.handler = conn.endpoint.AddHandler(filter, consumer, closer)

	consumer2 := func(msg *net.Message) error {
		return conn.endpoint.Send(*msg)
	}
	closer2 := func(err error) {
		conn.endpoint.Close()
	}
	endpoint.AddHandler(filter, consumer2, closer2)

	return conn, nil
}

type ghostService struct {
	info      services.ServiceInfo
	directory services.ServiceDirectoryProxy
	listen    net.Listener
	closeChan chan int
	user      string
	token     string
}

func (g *ghostService) handle(stream net.Stream,
	errors chan error, terminate chan struct{}) {
	_, err := newConnection(g, stream, errors, terminate)
	if err != nil {
		log.Print(err)
	}
}

func (g *ghostService) bg(errors chan error, terminate chan struct{}) {
	go func() {
		<-terminate
		g.listen.Close()
		g.directory.UnregisterService(g.info.ServiceId)
	}()
	for {
		stream, err := g.listen.Accept()
		if err != nil {
			errors <- err
			return
		}
		g.handle(stream, errors, terminate)
	}
}

// newGhost registers a new service using info.Name into w.to.session.
func newGhost(directory services.ServiceDirectoryProxy,
	info services.ServiceInfo) (*ghostService, error) {

	addr := util.NewUnixAddr()
	log.Printf("ghost %s: %s", info.Name, addr)
	listener, err := net.Listen(addr)
	if err != nil {
		return nil, fmt.Errorf("open socket %s: %s", addr, err)
	}

	info2 := services.ServiceInfo{
		Name:      info.Name,
		ServiceId: info.ServiceId,
		MachineId: util.MachineID(),
		ProcessId: util.ProcessID(),
		Endpoints: []string{
			addr,
		},
		SessionId: info.SessionId,
	}

	serviceID, err := directory.RegisterService(info2)
	if err != nil {
		return nil, fmt.Errorf("register %s: %s", info.Name, err)
	}

	if serviceID != info.ServiceId {
		return nil, fmt.Errorf("id do not match: %d vs %d",
			serviceID, info.ServiceId)
	}

	err = directory.ServiceReady(info2.ServiceId)
	if err != nil {
		return nil, fmt.Errorf("ready %s: %s", info.Name, err)
	}

	g := &ghostService{
		info:      info,
		listen:    listener,
		directory: directory,
	}
	return g, nil
}

type dir struct {
	session bus.Session
	url     string
	user    string
	token   string
}

type watcher struct {
	from dir
	to   dir
}

// Watcher duplicates entry from one servvice directory to another
func (w watcher) run(errors chan error, terminate chan struct{}) {

	proxies := services.Services(w.to.session)
	directoryTo, err := proxies.ServiceDirectory()
	if err != nil {
		errors <- err
		return
	}

	proxies = services.Services(w.from.session)
	directoryFrom, err := proxies.ServiceDirectory()
	unsubscribe, channel, err := directoryFrom.SubscribeServiceAdded()
	if err != nil {
		errors <- err
		return
	}

	go func() {
		<-terminate
		unsubscribe()
	}()

	for {
		added, ok := <-channel
		if !ok {
			break
		}
		info, err := directoryFrom.Service(added.Name)
		if err != nil {
			errors <- fmt.Errorf("%s added: %s", added.Name, err)
			return
		}
		_, err = directoryTo.Service(info.Name)
		if err == nil {
			// already registered
			continue
		}

		g, err := newGhost(directoryTo, info)
		if err != nil {
			errors <- fmt.Errorf("ghost %s: %s", added.Name, err)
			return
		}
		go g.bg(errors, terminate)
	}
	errors <- nil
}

// Terminator terminates
type Terminator interface {
	// Terminate stops the server.
	Terminate() error
	// Returns a channel to wait for the server terminaison.
	WaitTerminate() chan error
}

// firewall implements Terminator
type firewall struct {
	server     bus.Server
	from       watcher
	to         watcher
	reportErr  chan error
	collectErr chan error
	terminate  chan struct{}
}

func (f *firewall) WaitTerminate() chan error {
	return f.reportErr
}

func (f *firewall) Terminate() error {
	return f.server.Terminate()
}

// Firewall create a firewall which connect to internalURL and expose
// it at externalURL. It uses user, token to authenticate the incomming
// connections.
func Firewall(internalURL, internalUser, internalToken,
	externalURL, externalUser, externalToken string) (Terminator, error) {

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
	internal := dir{
		session: internalSession,
		url:     internalURL,
		user:    internalUser,
		token:   internalToken,
	}
	external := dir{
		session: externalSession,
		url:     externalURL,
		user:    externalUser,
		token:   externalToken,
	}
	fromWatcher := watcher{
		from: internal,
		to:   external,
	}
	toWatcher := watcher{
		from: external,
		to:   internal,
	}
	f := &firewall{
		server:     server,
		from:       fromWatcher,
		to:         toWatcher,
		reportErr:  make(chan error, 1),
		collectErr: make(chan error, 2),
		terminate:  make(chan struct{}),
	}
	go f.from.run(f.collectErr, f.terminate)
	go f.to.run(f.collectErr, f.terminate)
	go func() {
		var err error
		select {
		case err = <-server.WaitTerminate():
		case err = <-f.collectErr:
		}
		f.reportErr <- err
		close(f.terminate)
	}()

	return f, nil
}
