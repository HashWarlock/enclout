package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:   "enclout",
		Short: "Secure connector with TEE-attested SSH key derivation",
	}

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	})

	root.AddCommand(serveCmd())
	root.AddCommand(agentCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
