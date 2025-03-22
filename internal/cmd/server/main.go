package main

import (
	"fmt"
	"os"

	"securechat/internal/chat"
)

func main() {
	port := "8080"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	fmt.Println("Starting secure chat server...")
	server, err := chat.NewServer(port)
	if err != nil {
		fmt.Println("Error starting server:", err)
		os.Exit(1)
	}

	fmt.Println("Server started on port", port)
	fmt.Println("Use the client to request registration tokens")
	server.Run()
}
