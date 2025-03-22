package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"securechat/internal/chat"
	"securechat/internal/crypto"
)

func main() {
	// Generate or load TLS certificates
	err := crypto.GenerateSelfSignedCert()
	if err != nil {
		fmt.Println("Error setting up TLS certificates:", err)
		os.Exit(1)
	}

	port := "8080"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	fmt.Println("Starting secure chat server with TLS and message authentication...")
	server, err := chat.NewServer(port)
	if err != nil {
		fmt.Println("Error starting server:", err)
		os.Exit(1)
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down server gracefully...")
		server.Close()
		os.Exit(0)
	}()

	fmt.Println("Server started on port", port)
	fmt.Println("Use the client to request registration tokens")
	server.Run()
}
