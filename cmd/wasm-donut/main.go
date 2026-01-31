package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	wasmdonut "github.com/sliverarmory/wasm-donut"
)

type cliOptions struct {
	InPath     string
	InPathAlt  string
	InPathFile string
	OutPath    string
	OutPathAlt string
	Ext        string
	Args       string
	Params     string
	Class      string
	Method     string
	Function   string
	Domain     string
	Runtime    string
	Server     string
	ModName    string
	Decoy      string
	Arch       int
	ArchAlt    int
	Bypass     int
	Headers    int
	Entropy    int
	Compress   int
	ExitOpt    int
	Thread     bool
	Unicode    bool
	OEP        string
	Fork       string
	Format     int
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

			inPath, err := resolveString("input", opts.InPath, opts.InPathAlt, opts.InPathFile)
			if err != nil {
				return err
			}
			if inPath == "" {
				return errors.New("-in/--input is required")
			}

			outPath, err := resolveString("output", opts.OutPath, opts.OutPathAlt)
			if err != nil {
				return err
			}

			args, err := resolveString("args", opts.Args, opts.Params)
			if err != nil {
				return err
			}

			method, err := resolveString("method", opts.Method, opts.Function)
			if err != nil {
				return err
			}

			oepStr, err := resolveString("oep", opts.OEP, opts.Fork)
			if err != nil {
				return err
			}
			var oep uint32
			if oepStr != "" {
				parsed, err := strconv.ParseUint(oepStr, 0, 32)
				if err != nil {
					return fmt.Errorf("invalid oep value: %w", err)
				}
				oep = uint32(parsed)
			}

			arch := opts.Arch
			if opts.ArchAlt != 0 {
				if arch != wasmdonut.DonutArchX84 && arch != opts.ArchAlt {
					return fmt.Errorf("conflicting arch flags: %d vs %d", arch, opts.ArchAlt)
				}
				arch = opts.ArchAlt
			}

			genOpts := wasmdonut.GenerateOptions{
				Ext:      opts.Ext,
				Args:     args,
				Class:    opts.Class,
				Method:   method,
				Domain:   opts.Domain,
				Runtime:  opts.Runtime,
				Decoy:    opts.Decoy,
				Server:   opts.Server,
				ModName:  opts.ModName,
				Arch:     arch,
				Bypass:   opts.Bypass,
				Headers:  opts.Headers,
				Entropy:  opts.Entropy,
				Compress: opts.Compress,
				ExitOpt:  opts.ExitOpt,
				Thread:   opts.Thread,
				Unicode:  opts.Unicode,
				OEP:      oep,
				Format:   opts.Format,
			}

			return wasmdonut.GenerateToFile(ctx, inPath, outPath, genOpts)
		},
	}

	rootCmd.Flags().StringVarP(&opts.InPath, "input", "i", "", "path to input EXE/DLL/VBS/JS")
	rootCmd.Flags().StringVar(&opts.InPathAlt, "in", "", "alias for --input")
	rootCmd.Flags().StringVar(&opts.InPathFile, "file", "", "alias for --input")
	rootCmd.Flags().StringVarP(&opts.OutPath, "output", "o", "", "output path (defaults based on format)")
	rootCmd.Flags().StringVar(&opts.OutPathAlt, "out", "", "alias for --output")
	rootCmd.Flags().StringVar(&opts.Ext, "ext", "", "input file extension override (e.g. .exe, dll, vbs)")
	rootCmd.Flags().StringVarP(&opts.Class, "class", "c", "", "optional .NET class name")
	rootCmd.Flags().StringVarP(&opts.Domain, "domain", "d", "", "AppDomain name to create for .NET")
	rootCmd.Flags().StringVarP(&opts.Args, "args", "p", "", "optional parameters/command line for DLL method/function or EXE")
	rootCmd.Flags().StringVar(&opts.Params, "params", "", "alias for --args")
	rootCmd.Flags().StringVarP(&opts.Method, "method", "m", "", "optional method or DLL function")
	rootCmd.Flags().StringVar(&opts.Function, "function", "", "alias for --method")
	rootCmd.Flags().StringVarP(&opts.Runtime, "runtime", "r", "", "CLR runtime version")
	rootCmd.Flags().StringVarP(&opts.Server, "server", "s", "", "HTTP server URL for hosting module")
	rootCmd.Flags().StringVarP(&opts.ModName, "modname", "n", "", "module name for HTTP staging")
	rootCmd.Flags().StringVarP(&opts.Decoy, "decoy", "j", "", "optional path of decoy module")
	rootCmd.Flags().IntVarP(&opts.Arch, "arch", "a", wasmdonut.DonutArchX84, "target arch: 1=x86, 2=amd64, 3=x86+x64")
	rootCmd.Flags().IntVar(&opts.ArchAlt, "cpu", 0, "alias for --arch")
	rootCmd.Flags().IntVarP(&opts.Bypass, "bypass", "b", wasmdonut.DonutBypassContinue, "bypass AMSI/WLDP/ETW: 1=None, 2=Abort, 3=Continue")
	rootCmd.Flags().IntVarP(&opts.Headers, "headers", "k", wasmdonut.DonutHeadersOverwrite, "preserve PE headers: 1=Overwrite, 2=Keep")
	rootCmd.Flags().IntVarP(&opts.Entropy, "entropy", "e", wasmdonut.DonutEntropyDefault, "entropy: 1=None, 2=Random names, 3=Random+Encrypt")
	rootCmd.Flags().IntVarP(&opts.Format, "format", "f", wasmdonut.DonutFormatBinary, "output format: 1=Binary, 2=Base64, 3=C, 4=Ruby, 5=Python, 6=PowerShell, 7=C#, 8=Hex, 9=UUID")
	rootCmd.Flags().IntVarP(&opts.ExitOpt, "exit", "x", wasmdonut.DonutExitThread, "exit behavior: 1=thread, 2=process, 3=block")
	rootCmd.Flags().IntVarP(&opts.Compress, "compress", "z", wasmdonut.DonutCompressNone, "compression: 1=None, 2=aPLib, 3=LZNT1, 4=Xpress, 5=Xpress Huffman")
	rootCmd.Flags().BoolVarP(&opts.Thread, "thread", "t", false, "run unmanaged EXE entrypoint as a thread")
	rootCmd.Flags().BoolVarP(&opts.Unicode, "unicode", "w", false, "pass DLL arguments as UNICODE")
	rootCmd.Flags().StringVarP(&opts.OEP, "oep", "y", "", "fork offset relative to host executable")
	rootCmd.Flags().StringVar(&opts.Fork, "fork", "", "alias for --oep")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func resolveString(label string, values ...string) (string, error) {
	var chosen string
	for _, v := range values {
		if v == "" {
			continue
		}
		if chosen == "" {
			chosen = v
			continue
		}
		if chosen != v {
			return "", fmt.Errorf("conflicting %s values: %q vs %q", label, chosen, v)
		}
	}
	return chosen, nil
}
