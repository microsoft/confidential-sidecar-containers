package main

import (
	"context"
	"log"
	"net"
	"testing"

	server "github.com/Microsoft/confidential-sidecar-containers/pkg/grpc/grpcserver"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/grpc/key_provider"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var (
	lis         *bufconn.Listener
	sayHelloRes string = "Hello this is a test!"
)

// The benefit of this approach is that you're still getting network behavior, but over an in-memory connection without using OS-level resources like ports that may or may not clean up quickly. And it allows you to test it the way it's actually used, and it gives you proper streaming behavior.
// I don't have a streaming example off the top of my head, but the magic sauce is all above. It gives you all of the expected behaviors of a normal network connection. The trick is setting the WithDialer option as shown, using the bufconn package to create a listener that exposes its own dialer. I use this technique all the time for testing gRPC services and it works great.
func init() {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	key_provider.RegisterKeyProviderServiceServer(s, &server.Server{})
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func TestSayHello(t *testing.T) {
	ctx := context.Background()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			t.Fatalf("Failed to close connection: %s\n", err)
		}
	}()

	client := key_provider.NewKeyProviderServiceClient(conn)
	resp, err := client.SayHello(ctx, &key_provider.HelloRequest{Name: "this is a test!"})
	if err != nil {
		t.Fatalf("grpc exposed endpoint failed with error: %v", err)
	}
	log.Printf("Response: %+v, expected response message '%s'.", resp, sayHelloRes)

	if resp.Message != sayHelloRes {
		t.Errorf("grpc exposed endpoint failed and received unexpected result.")
	}
}
