package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pqswitch/scanner/internal/config"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "pqswitch",
	Short: "Post-Quantum Cryptography migration scanner",
	Long: `PQSwitch is a CLI tool that scans codebases and infrastructure for 
classical cryptographic implementations and helps migrate to post-quantum 
cryptography (PQC) standards.`,
	Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
}

// Old scan command removed - functionality merged into enhanced scan (now renamed to 'scan')

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate patches and pull requests",
	Long:  `Generate patches and pull requests to migrate from classical to post-quantum cryptography.`,
}

var patchCmd = &cobra.Command{
	Use:   "patch [path]",
	Short: "Generate patches for detected crypto usage",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Patch generation not yet implemented")
		return nil
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&config.ConfigFile, "config", "", "config file (default is $HOME/.pqswitch.yaml)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(generateCmd)
	generateCmd.AddCommand(patchCmd)

	// Bind flags to viper
	if err := viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose")); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to bind verbose flag: %v\n", err)
	}
}

func initConfig() {
	if config.ConfigFile != "" {
		viper.SetConfigFile(config.ConfigFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".pqswitch")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
