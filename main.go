package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"akko/internal/akko"

	"golang.org/x/term"
)

// アプリケーションのバージョン（Taskfileで埋め込まれる）
var appVersion = ""

func main() {
	var keyArg string
	var output string
	var force bool
	var archive bool
	var showVersion bool
	var recursive bool
	var silent bool
	var highSecurity bool
	var expiryArg string

	flag.StringVar(&keyArg, "key", "", "path to key file")
	flag.StringVar(&output, "output", "", "output file path")
	flag.StringVar(&output, "o", "", "output file path (shorthand)")
	flag.BoolVar(&force, "force", false, "overwrite output file if it exists")
	flag.BoolVar(&archive, "archive", false, "bundle multiple inputs into a single encrypted archive")
	flag.BoolVar(&archive, "a", false, "bundle multiple inputs into a single encrypted archive (shorthand)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&showVersion, "v", false, "print version and exit (shorthand)")
	flag.BoolVar(&recursive, "r", false, "recurse into directories given as input")
	flag.BoolVar(&silent, "silent", false, "suppress the per-file progress output")
	flag.BoolVar(&highSecurity, "secure", false, "enable high-security KDF parameters (slower)")
	flag.StringVar(&expiryArg, "expiry", "", "expiry datetime for encrypted output (YYYY/MM/DD HH:MM)")
	var showHeader bool
	flag.BoolVar(&showHeader, "header", false, "show akko file header information only")
	flag.Parse()

	if showVersion {
		fmt.Fprintln(os.Stdout, version())
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}

	inputs, err := expandInputs(flag.Args(), recursive)
	if err != nil {
		fatal(err)
	}
	if len(inputs) == 0 {
		fatal(errors.New("no input files matched"))
	}

	// the shell may have already expanded a wildcard before akko sees the
	// arguments, so also confirm whenever multiple files ended up resolved.
	if (hasWildcard(flag.Args()) || len(inputs) > 1) && !confirmWildcardInputs(inputs) {
		fmt.Fprintln(os.Stderr, "aborted")
		os.Exit(1)
	}

	// If the user only wants header information, handle that without
	// prompting for a password or performing full decrypt/encrypt operations.
	if showHeader {
		exitCode := 0
		for _, input := range inputs {
			if !silent {
				fmt.Fprintf(os.Stderr, "processing: %s\n", input)
			}
			mode, err := akko.DetectMode(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %s\n", input, classifyError(err))
				exitCode = 1
				continue
			}
			if mode == akko.ModeEncrypt {
				fmt.Fprintf(os.Stdout, "%s: not an akko file\n", input)
				continue
			}
			h, err := akko.PeekHeader(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %s\n", input, classifyError(err))
				exitCode = 1
				continue
			}
			// Print header fields in a human-friendly way.
			fmt.Fprintf(os.Stdout, "%s:\n", input)
			fmt.Fprintf(os.Stdout, "  version: %d\n", h.Version)
			fmt.Fprintf(os.Stdout, "  algorithm: %d\n", h.Algorithm)
			fmt.Fprintf(os.Stdout, "  kdf: %d\n", h.KDF)
			// KDF Memory is stored as KiB (Argon2 expects memory in KiB).
			// Display it in MiB for user-friendliness.
			fmt.Fprintf(os.Stdout, "  kdf.memory: %d MiB\n", h.KDFParams.Memory/1024)
			fmt.Fprintf(os.Stdout, "  kdf.iterations: %d\n", h.KDFParams.Iterations)
			fmt.Fprintf(os.Stdout, "  kdf.parallelism: %d\n", h.KDFParams.Parallelism)
			fmt.Fprintf(os.Stdout, "  salt: %s\n", hex.EncodeToString(h.Salt[:]))
			fmt.Fprintf(os.Stdout, "  nonce_base: %s\n", hex.EncodeToString(h.NonceBase[:]))
			fmt.Fprintf(os.Stdout, "  original_mode: %o\n", h.OriginalMode)
			fmt.Fprintf(os.Stdout, "  original_ext: %q\n", h.OriginalExt)
			if h.ExpiryUnix > 0 {
				expiry := formatExpiryForDisplay(time.Unix(h.ExpiryUnix, 0).Local())
				fmt.Fprintf(os.Stdout, "  expiry: %s\n", expiry)
			} else {
				fmt.Fprintf(os.Stdout, "  expiry: none\n")
			}
		}
		os.Exit(exitCode)
	}

	if highSecurity {
		fmt.Fprintf(os.Stdout, "高セキュリティモードで暗号化します\n")
		akko.SetDefaultKDFParams(akko.HighSecurityKDFParams)
	}

	expiryUnix, err := parseExpiry(expiryArg)
	if err != nil {
		fatal(err)
	}
	akko.SetDefaultExpiryUnix(expiryUnix)

	password, err := resolvePassword(keyArg)
	if err != nil {
		fatal(err)
	}

	if archive {
		os.Exit(runArchiveMode(inputs, output, password, force, silent))
	}

	if len(inputs) > 1 && output != "" {
		fatal(errors.New("-output cannot be used with multiple input files"))
	}

	exitCode := 0
	for _, input := range inputs {
		if !silent {
			fmt.Fprintf(os.Stderr, "processing: %s\n", input)
		}
		mode, outPath, count, err := akko.Action(input, output, password, force, entryPrinter(silent))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", input, classifyError(err))
			exitCode = 1
			continue
		}
		printResult(mode, outPath, count)
	}
	os.Exit(exitCode)
}

// entryPrinter returns a callback that prints each archive member as it is
// packed/extracted (similar to `tar -v`), or nil when silent is set.
func entryPrinter(silent bool) func(string) {
	if silent {
		return nil
	}
	return func(name string) {
		fmt.Fprintf(os.Stderr, "  %s\n", name)
	}
}

// runArchiveMode bundles inputs that need encrypting into a single akko
// archive file, and decrypts (auto-extracting archives) any inputs that are
// already akko files, individually.
func runArchiveMode(inputs []string, output string, password []byte, force bool, silent bool) int {
	exitCode := 0
	var toEncrypt, toDecrypt []string

	for _, in := range inputs {
		mode, err := akko.DetectMode(in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", in, classifyError(err))
			exitCode = 1
			continue
		}
		if mode == akko.ModeEncrypt {
			toEncrypt = append(toEncrypt, in)
		} else {
			toDecrypt = append(toDecrypt, in)
		}
	}

	if len(toEncrypt) > 0 {
		if !silent {
			fmt.Fprintf(os.Stderr, "processing: %d files into archive\n", len(toEncrypt))
		}
		outPath, err := akko.EncryptArchive(toEncrypt, output, password, force, entryPrinter(silent))
		if err != nil {
			fmt.Fprintf(os.Stderr, "archive: %s\n", classifyError(err))
			exitCode = 1
		} else {
			fmt.Fprintf(os.Stdout, "encrypted archive (%d files): %s\n", len(toEncrypt), outPath)
		}
	}

	if len(toDecrypt) > 1 && output != "" {
		fmt.Fprintln(os.Stderr, "-output cannot be used with multiple archive inputs to decrypt")
		return 1
	}
	for _, in := range toDecrypt {
		if !silent {
			fmt.Fprintf(os.Stderr, "processing: %s\n", in)
		}
		mode, outPath, count, err := akko.Action(in, output, password, force, entryPrinter(silent))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", in, classifyError(err))
			exitCode = 1
			continue
		}
		printResult(mode, outPath, count)
	}

	return exitCode
}

func printResult(mode akko.Mode, outPath string, count int) {
	if count < 0 {
		count = 0
	}
	switch mode {
	case akko.ModeEncrypt:
		fmt.Fprintf(os.Stdout, "encrypted (%d files): %s\n", count, outPath)
	case akko.ModeDecryptArchive:
		fmt.Fprintf(os.Stdout, "decrypted archive (%d files): %s\n", count, outPath)
	default:
		fmt.Fprintf(os.Stdout, "decrypted (%d files): %s\n", count, outPath)
	}
}

func hasWildcard(args []string) bool {
	for _, a := range args {
		if strings.ContainsAny(a, "*?[") {
			return true
		}
	}
	return false
}

// confirmWildcardInputs asks the user to confirm the expanded file list before
// proceeding, to avoid accidentally operating on unintended files.
func confirmWildcardInputs(inputs []string) bool {
	fmt.Fprintln(os.Stderr, "以下のファイルが対象になります:")
	for _, in := range inputs {
		fmt.Fprintf(os.Stderr, "  %s\n", in)
	}
	fmt.Fprint(os.Stderr, "続行しますか？ [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

// expandInputs resolves glob patterns (e.g. "sample_*.txt") into regular files,
// so wildcards work even on shells/platforms that don't expand them themselves.
// Symlinks are never followed; when recursive is true, directories are walked
// recursively and only regular files within them are included.
func expandInputs(args []string, recursive bool) ([]string, error) {
	seen := make(map[string]bool)
	var result []string
	for _, arg := range args {
		matches, err := filepath.Glob(arg)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", arg, err)
		}
		if len(matches) == 0 {
			if !seen[arg] {
				seen[arg] = true
				result = append(result, arg)
			}
			continue
		}
		for _, m := range matches {
			st, err := os.Lstat(m)
			if err != nil {
				continue
			}
			if st.Mode()&os.ModeSymlink != 0 {
				continue // シンボリックリンクは対象外
			}
			if st.IsDir() {
				if !recursive {
					return nil, fmt.Errorf("%s はディレクトリです（再帰的に処理するには -r を指定してください）", m)
				}
				files, err := collectRegularFiles(m)
				if err != nil {
					return nil, err
				}
				for _, f := range files {
					if !seen[f] {
						seen[f] = true
						result = append(result, f)
					}
				}
				continue
			}
			if !st.Mode().IsRegular() {
				continue
			}
			if !seen[m] {
				seen[m] = true
				result = append(result, m)
			}
		}
	}
	return result, nil
}

// collectRegularFiles walks root recursively, returning regular files only.
// Symlinks (to files or directories) are skipped without being followed.
func collectRegularFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: akko [-key <keyfile>] [-output|-o <path>] [-force] [-archive|-a] [-r] [-silent] [-expiry \"YYYY/MM/DD HH:MM\"] [-header] [-version|-v] <input...>")
}

func version() string {
	if appVersion == "" {
		return "akko dev"
	}
	return "akko " + appVersion
}

func resolvePassword(keyArg string) ([]byte, error) {
	if keyArg != "" {
		return readKeyFile(keyArg)
	}

	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	pw = []byte(strings.TrimRight(string(pw), "\r\n"))
	if len(pw) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	return pw, nil
}

func readKeyFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("key file not found: %s", path)
		}
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("key file must be a regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = []byte(strings.TrimRight(string(b), "\r\n"))
	if len(b) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	return b, nil
}

func fatal(err error) {
	msg := classifyError(err)
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func classifyError(err error) string {
	switch {
	case errors.Is(err, akko.ErrNotAkkoFile):
		return "invalid akko file"
	case errors.Is(err, akko.ErrInvalidAkkoFile):
		return "invalid akko file"
	case errors.Is(err, akko.ErrUnsupportedVersion):
		return "unsupported akko version"
	case errors.Is(err, akko.ErrUnsupportedAlgorithm):
		return "unsupported encryption algorithm"
	case errors.Is(err, akko.ErrUnsupportedKDF):
		return "unsupported KDF"
	case errors.Is(err, akko.ErrAuthFailed):
		return "invalid password or corrupted file"
	case errors.Is(err, akko.ErrExpired):
		return "encrypted file has expired and cannot be decrypted"
	case errors.Is(err, io.EOF):
		return "invalid akko file"
	default:
		return err.Error()
	}
}

const expiryLayout = "2006/01/02 15:04"

func parseExpiry(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	t, err := time.ParseInLocation(expiryLayout, raw, time.Local)
	if err != nil {
		return 0, fmt.Errorf("invalid -expiry format: %q (expected %s)", raw, expiryLayout)
	}
	// Treat minute-granularity input as valid through HH:MM:59.
	return t.Add(59 * time.Second).Unix(), nil
}

func formatExpiryForDisplay(t time.Time) string {
	return fmt.Sprintf("%s %s (UTC%s)", t.Format(expiryLayout), t.Format("MST"), t.Format("-07:00"))
}
