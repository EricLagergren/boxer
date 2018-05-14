package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/EricLagergren/boxer/boxer"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	chunk     = flag.Int("chunk", boxer.DefaultChunkSize, "set the chunk size")
	nonceFile = flag.String("nonce", "", "file to read nonce from")
	keyFile   = flag.String("key", "", "file to read key from")
	inFile    = flag.String("in", "", "input file, defaults to stdin")
	outFile   = flag.String("out", "", "output file, defaults to stdout")
	dec       = flag.Bool("dec", false, "true if file should be decrypted")
)

func main() {
	flag.Parse()

	var nonce [16]byte
	var key [32]byte

	err := readData("Input nonce:", *nonceFile, nonce[:])
	if err != nil {
		log.Fatalln(err)
	}
	err = readData("Input key:", *keyFile, key[:])
	if err != nil {
		log.Fatalln(err)
	}

	in := io.ReadCloser(os.Stdin)
	if *inFile != "" {
		in, err = os.Open(*inFile)
		if err != nil {
			log.Fatalln(err)
		}
		defer in.Close()
	}

	out := io.WriteCloser(os.Stdout)
	if *outFile != "" {
		out, err = os.Create(*outFile)
		if err != nil {
			log.Fatalln(err)
		}
		defer out.Close()
	}

	if *dec {
		in, err = boxer.NewDecryptor(in, &nonce, &key)
		defer in.Close()
	} else {
		out, err = boxer.NewEncryptorSize(out, &nonce, &key, *chunk)
		defer out.Close()
	}
	if err != nil {
		log.Fatalln(err)
	}

	if _, err := io.Copy(out, in); err != nil {
		log.Fatalln(err)
	}
}

func readData(what, from string, to []byte) error {
	if from != "" {
		file, err := os.Open(from)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.ReadFull(file, to)
		return err
	}

	infd := int(os.Stdin.Fd())
	state, err := terminal.GetState(infd)
	if err != nil {
		return err
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		for range ch {
			terminal.Restore(infd, state)
			os.Exit(1)
		}
	}()

	if !strings.HasSuffix(what, "\n") {
		what += "\n"
	}
	os.Stdout.WriteString(what)
	b, err := terminal.ReadPassword(infd)
	if err != nil {
		return err
	}
	if len(b) != len(to) {
		return fmt.Errorf("invalid input length, wanted %d got %d", len(to), len(b))
	}
	copy(to, b)
	return nil
}
