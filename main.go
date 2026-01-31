package main

import (
	"context"
	"os"

	"github.com/spf13/cobra"
)

type cliOptions struct {
	InPath   string
	OutPath  string
	Ext      string
	Args     string
	Class    string
	Method   string
	Arch     int
	Entropy  int
	Compress int
	ExitOpt  int
}

func main() {
	opts := &cliOptions{}

	rootCmd := &cobra.Command{
		Use:          "wasm-donut",
		Short:        "Generate Donut shellcode using the wasm build",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			genOpts := GenerateOptions{
				Ext:      opts.Ext,
				Args:     opts.Args,
				Class:    opts.Class,
				Method:   opts.Method,
				Arch:     opts.Arch,
				Entropy:  opts.Entropy,
				Compress: opts.Compress,
				ExitOpt:  opts.ExitOpt,
			}
			return GenerateToFile(ctx, opts.InPath, opts.OutPath, genOpts)
		},
	}

	rootCmd.Flags().StringVar(&opts.InPath, "in", "", "path to input EXE/DLL/VBS/JS")
	rootCmd.Flags().StringVar(&opts.OutPath, "out", "loader.bin", "output shellcode path")
	rootCmd.Flags().StringVar(&opts.Ext, "ext", "", "input file extension override (e.g. .exe, dll, vbs)")
	rootCmd.Flags().StringVar(&opts.Args, "args", "", "optional arguments for the module")
	rootCmd.Flags().StringVar(&opts.Class, "class", "", "optional .NET class name")
	rootCmd.Flags().StringVar(&opts.Method, "method", "", "optional method or DLL function")
	rootCmd.Flags().IntVar(&opts.Arch, "arch", DonutArchX84, "target arch: 1=x86, 2=x64, 3=x86+x64")
	rootCmd.Flags().IntVar(&opts.Entropy, "entropy", DonutEntropyNone, "entropy: 1=none, 2=random names, 3=random+encrypt")
	rootCmd.Flags().IntVar(&opts.Compress, "compress", DonutCompressNone, "compression: 1=none, 2=aplib")
	rootCmd.Flags().IntVar(&opts.ExitOpt, "exit", DonutExitThread, "exit: 1=thread, 2=process, 3=block")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
