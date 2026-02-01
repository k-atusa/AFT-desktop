// test798b : project USAG AFT-desktop cli
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// command line parser
type Config struct {
	Mode   string
	Target string
	Output string
	PW     string
	KF     []byte
	Msg    string
}

func (cfg *Config) Init() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError) // empty string means auto
	fs.StringVar(&cfg.Mode, "m", "help", "work mode: import, export, view, trim, version, help")
	fs.StringVar(&cfg.PW, "o", "", "output folder")
	fs.StringVar(&cfg.PW, "pw", "", "password")
	fs.StringVar(&cfg.Msg, "msg", "", "message")

	// get keyfile
	kfpath := ""
	fs.StringVar(&kfpath, "kf", "", "key file path")

	// parse and get target folder
	fs.Parse(os.Args[1:])
	cfg.Target = fs.Arg(0)

	if kfpath == "" {
		cfg.KF = nil
	} else if _, err := os.Stat(kfpath); err == nil { // file
		fmt.Println("reading keyfile")
		cfg.KF, err = os.ReadFile(kfpath)
		if err != nil {
			fmt.Println(err)
			cfg.KF = nil
		}
	}
	if len(cfg.KF) > 1024 {
		fmt.Println("keyfile is truncated to 1024B")
		cfg.KF = cfg.KF[:1024]
	}
}

// main functions
func f_import() error {
	// check arguments
	if Cfg.Target == "" || Cfg.Output == "" {
		return errors.New("target and output are required for import")
	}
	info, err := os.Stat(Cfg.Output)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("output is not a directory")
	}
	if err := os.MkdirAll(Cfg.Output, 0755); err != nil {
		return err
	}

	// make AVault
	v := &AVault{
		Path:     Cfg.Output,
		Limit:    512 * 1024 * 1024,
		Algo:     "ecc1",
		Ext:      "webp",
		TreeView: make(map[string][]string),
		PtoCtbl:  make(map[string]string),
		CtoPtbl:  make(map[string]string),
	}
	if err := v.NewKeypair(); err != nil {
		return err
	}
	if err := v.StoreAccount(Cfg.PW, Cfg.KF, Cfg.Msg); err != nil {
		return err
	}

	// search target folder
	entries, err := os.ReadDir(Cfg.Target)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fullPath := filepath.Join(Cfg.Target, entry.Name())
		fmt.Printf("Adding: %s\n", fullPath)
		err = v.Add(fullPath, "")
		if err != nil {
			return err
		}
	}

	fmt.Printf("\nSuccessfully imported vault at: %s\n", v.Path)
	return nil
}

func f_export() error {
	// check arguments
	if Cfg.Target == "" || Cfg.Output == "" {
		return errors.New("targetand output are required for export")
	}
	if err := os.MkdirAll(Cfg.Output, 0755); err != nil {
		return err
	}

	// load vault
	v := &AVault{Path: Cfg.Target}
	msg, err := v.Load(Cfg.PW, Cfg.KF)
	if msg != "" {
		fmt.Printf("[MSG]: %s\n", msg)
	}
	if err != nil {
		return err
	}
	fmt.Println("Vault unlocked")

	// restore files
	for plainName := range v.PtoCtbl {
		// folder: make directory
		if strings.HasSuffix(plainName, "/") {
			dirPath := filepath.Join(Cfg.Output, plainName)
			if err := os.MkdirAll(dirPath, 0755); err != nil {
				return err
			}
			fmt.Printf("Created directory: %s\n", plainName)
			continue
		}

		// file: read data
		data, err := v.Read(plainName)
		if err != nil {
			fmt.Printf("Failed to read %s: %v\n", plainName, err)
			continue
		}

		// write file
		targetFilePath := filepath.Join(Cfg.Output, plainName)
		if err := os.MkdirAll(filepath.Dir(targetFilePath), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(targetFilePath, data, 0644); err != nil {
			return err
		}
		fmt.Printf("Exported file: %s\n", plainName)
	}

	fmt.Printf("\nSuccessfully exported to: %s\n", Cfg.Output)
	return nil
}

func f_view() error {
	// 볼트의 모든 정보와 파일 리스트를 보여줌
}

func f_trim() error {
	// 볼트를 트림하고 키 쌍을 새로 생성한 후 모든 파일을 업데이트
}

var Cfg Config

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("critical: %v", err)
		}
	}()
	var err error
	Cfg.Init()
	fmt.Println("Configuration completed")
	switch Cfg.Mode {
	case "import":
		err = f_import()
	case "export":
		err = f_export()
	case "view":
		err = f_view()
	case "trim":
		err = f_trim()
	case "version":
		fmt.Println("2026 @k-atusa [USAG] AFT-lite v0.1")
	default: // help
		fmt.Println("-m mode [import|export|view|trim|version|help] -o outdir -pw password -kf keyfile -msg message")
		fmt.Println("import: target -> outdir +(pw, kf, msg)")
		fmt.Println("export: target -> outdir +(pw, kf)")
		fmt.Println("view: list all files +(pw, kf)")
		fmt.Println("trim: trim and rebuild +(pw, kf)")
	}
	if err != nil {
		fmt.Printf("\nerror: %v\n", err)
	}
}
