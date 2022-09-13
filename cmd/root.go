package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tvd",
	Short: "tenable vulnerability diff - a pipeline utility",
	Long:  " \n tenable vulnerability diff is a pipeline utility leveraging tenables api \n to check you haven't introduced new vulnerabilities into your deployment.",
}

func init() {
	//remove help shorthand for consistency due to clash with high in run
	rootCmd.PersistentFlags().BoolP("help", "", false, "help for this command")
}

func Execute() error {
	return rootCmd.Execute()
}
