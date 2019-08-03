package bouncer_test

import (
	"fmt"
	"log"
	"sync"
	"testing"

	"github.com/lugu/bouncer"
	"github.com/lugu/qiloop"
	"github.com/lugu/qiloop/bus"
	"github.com/lugu/qiloop/bus/directory"
	"github.com/lugu/qiloop/bus/services"
	"github.com/lugu/qiloop/bus/util"
	"github.com/lugu/qiloop/examples/pong"
)

func TestFireWall(t *testing.T) {

	internalURL := util.NewUnixAddr()
	internalUser := "secret"
	internalToken := "secret"

	externalURL := util.NewUnixAddr()
	externalUser := "secret" // FIXME
	externalToken := "secret"

	log.Printf("internal: %s", internalURL)
	log.Printf("external: %s", externalURL)

	passwords := map[string]string{
		internalUser: internalToken,
	}
	auth := bus.Dictionary(passwords)
	internalDirectory, err := directory.NewServer(internalURL, auth)
	if err != nil {
		t.Fatal(err)
	}
	defer internalDirectory.Terminate()

	firewall, err := bouncer.Firewall(internalURL, internalUser, internalToken,
		externalURL, externalUser, externalToken)
	if err != nil {
		t.Fatal(err)
	}
	defer firewall.Terminate()

	internalA := util.NewUnixAddr()
	log.Printf("internal A: %s", internalA)
	internalServiceA, err := NewService(internalURL, internalA,
		"A", internalUser, internalToken)
	if err != nil {
		t.Fatal(err)
	}

	// test normal connection to A
	err = NewClient(internalURL, "A", internalUser, internalToken)
	if err != nil {
		t.Fatal(err)
	}

	// test connection to A through the firewall
	err = NewClient(externalURL, "A", externalUser, externalToken)
	if err != nil {
		t.Error(err)
	}

	// external service
	externalB := util.NewUnixAddr()
	log.Printf("external B: %s", externalB)
	externalServiceB, err := NewService(externalURL, externalB,
		"B", externalUser, externalToken)
	if err != nil {
		t.Fatal(err)
	}

	// test connection to B from inside
	err = NewClient(externalURL, "B", externalUser, externalToken)
	if err != nil {
		t.Error(err)
	}

	// test connection to B from inside
	err = NewClient(internalURL, "B", internalUser, internalToken)
	if err != nil {
		t.Error(err)
	}

	select {
	case err = <-internalDirectory.WaitTerminate():
		t.Fatal(err)
	case err = <-firewall.WaitTerminate():
		t.Fatal(err)
	case err = <-internalServiceA.WaitTerminate():
		t.Fatal(err)
	case err = <-externalServiceB.WaitTerminate():
		t.Fatal(err)
	default:
	}
}

func NewService(sessionURL, listenURL, serviceName,
	user, token string) (qiloop.Server, error) {

	session, err := qiloop.NewSession(sessionURL, user, token)
	if err != nil {
		panic(err)
	}

	var auth bus.Authenticator = bus.Yes{}
	if user != "" {
		passwords := map[string]string{
			user: token,
		}
		auth = bus.Dictionary(passwords)
	}
	server, err := services.NewServer(session, listenURL, auth)
	if err != nil {
		return nil, err
	}

	service := pong.PingPongObject(pong.PingPongImpl())
	_, err = server.NewService(serviceName, service)
	if err != nil {
		return nil, err
	}

	log.Print("Service running: " + serviceName)
	return server, nil
}

func NewClient(sessionURL, serviceName, user, token string) error {

	session, err := qiloop.NewSession(sessionURL, user, token)
	if err != nil {
		return fmt.Errorf("Session error: %s", err)
	}
	defer session.Terminate()

	proxy, err := session.Proxy(serviceName, 1)
	if err != nil {
		return fmt.Errorf("Proxy error: %s", err)
	}
	client := pong.MakePingPong(session, proxy)

	// subscribe to the signal "pong" of the ping pong service.
	cancel, pong, err := client.SubscribePong()
	if err != nil {
		return err
	}
	defer cancel()

	var count = 10

	var wait sync.WaitGroup
	wait.Add(count)

	go func() {
		for i := 0; i < count; i++ {
			answer := <-pong
			if answer != "hello" {
				log.Printf("Wrong event: %s", answer)
			}
			log.Print("pong receive")
			wait.Done()
		}
	}()

	for i := 0; i < count; i++ {
		client.Ping("hello")
		log.Print("ping sent")
	}

	wait.Wait()
	return nil
}
