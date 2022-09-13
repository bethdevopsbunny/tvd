package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

func init() {
	//remove help shorthand for consistency due to clash with high in run
	versionCmd.PersistentFlags().BoolP("help", "", false, "help for this command")

	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of tvd",
	Long:  `Print the version number of tvd`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("tvd - v0.1")
	},
}
