package boxer

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

var (
	nonce = &[16]byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4}
	key   = new([32]byte)
	data  []byte
)

func TestMain(m *testing.M) {
	var err error
	data, err = ioutil.ReadFile("/usr/share/dict/words")
	if err != nil {
		data = make([]byte, 1<<16)
		if _, err := rand.Read(data); err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}

func testCrypt(t *testing.T, e *Encryptor, r io.Reader, data []byte) {
	if _, err := e.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	d, err := NewDecryptor(r, nonce, key)
	if err != nil {
		t.Fatal(err)
	}

	var buf2 bytes.Buffer
	if _, err := io.Copy(&buf2, d); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, buf2.Bytes()) {
		t.Fatalf("data len == %d, got len == %d",
			len(data), len(buf2.Bytes()))
	}
}

func TestValidCrypt(t *testing.T) {
	var buf bytes.Buffer
	testCrypt(t, NewEncryptor(&buf, nonce, key), &buf, data)
}

func TestValidCryptSize(t *testing.T) {
	var buf bytes.Buffer
	e, err := NewEncryptorSize(&buf, nonce, key, 2<<14)
	if err != nil {
		t.Fatal(err)
	}
	testCrypt(t, e, &buf, data)
}

func TestInvalidSize(t *testing.T) {
	if _, err := NewEncryptorSize(nil, nonce, key, 1<<63-1); err == nil {
		t.Fatal("wanted err != nil, got err == nil")
	}
}

func TestLargeCrypt(t *testing.T) {
	file, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	h1 := sha256.New()
	enc := NewEncryptor(file, nonce, key)
	tee := io.TeeReader(rand.Reader, h1)
	if _, err := io.CopyN(enc, tee, 1<<30); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	h2 := sha256.New()
	if _, err := file.Seek(0, os.SEEK_SET); err != nil {
		t.Fatal(err)
	}
	dec, err := NewDecryptor(file, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(h2, dec); err != nil {
		t.Fatal(err)
	}
	if err := dec.Close(); err != nil {
		t.Fatal(err)
	}
	if s1, s2 := h1.Sum(nil), h2.Sum(nil); !bytes.Equal(s1, s2) {
		t.Fatalf(`
expected: %#x
got     : %#x
`, s1, s2)
	}
}
