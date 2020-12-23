// +build !js

package quic

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/pion/transport/test"
	"github.com/stretchr/testify/assert"
)

func TestTransport_E2E(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	url := "localhost:50000"

	cert, key, err := GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	cfgA := &Config{Certificate: cert, PrivateKey: key}

	cert, key, err = GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	cfgB := &Config{Certificate: cert, PrivateKey: key}

	srvErr := make(chan error)

	var tb *Transport
	var lisClose io.Closer

	var (
		clientTx bytes.Buffer // control buffer for comparison

		clientBidiRx bytes.Buffer // receive buffer of bidirectional stream for client
		serverBidiRx bytes.Buffer // receive buffer of bidirectional stream for server

		serverUnidiRx bytes.Buffer // receive buffer of unidirectional stream for server

		clientDone sync.WaitGroup
		serverDone sync.WaitGroup
	)

	go func() { // server accept and read spawn
		defer close(srvErr)

		var sErr error
		tb, lisClose, sErr = newServer(url, cfgB)
		if sErr != nil {
			t.Log("newServer err:", err)
			srvErr <- sErr
			return
		}

		tb.OnBidirectionalStream(func(stream *BidirectionalStream) {
			serverDone.Add(1)
			go readBidiLoop(t, stream, &serverBidiRx, &serverDone) // Read to pull incoming messages
		})
		tb.OnUnidirectionalStream(func(stream *ReadableStream) {
			serverDone.Add(1)
			go readUnidiLoop(t, stream, &serverUnidiRx, &serverDone)
		})
	}()

	// client dial and send/write
	ta, err := NewTransport(url, cfgA)
	if err != nil {
		t.Fatal(err)
	}

	err = <-srvErr
	if err != nil {
		t.Fatal(err)
	}

	stream, err := ta.CreateBidirectionalStream()
	if err != nil {
		t.Fatal(err)
	}

	writablestream, err := ta.CreateUnidirectionalStream()
	if err != nil {
		t.Fatal(err)
	}

	// Read to pull incoming messages, should stay empty
	clientDone.Add(1)
	go readBidiLoop(t, stream, &clientBidiRx, &clientDone)

	count := 512  // how many patterns to send
	repeat := 128 // how often to repeat the testData pattern

	// sent side
	var buf [2]byte
	for i := 0; i < count; i++ {
		testData := bytes.Repeat([]byte(fmt.Sprintf("%04d", i)), repeat)
		binary.BigEndian.PutUint16(buf[:], uint16(i))
		msg := append(testData, buf[0], buf[1])

		_, _ = clientTx.Write(msg) // writing to a buffer never fails (hi golint)

		data := StreamWriteParameters{Data: msg}
		if i == count-1 {
			data.Finished = true
		}
		err = stream.Write(data)
		if err != nil {
			t.Fatal(err)
		}

		err = writablestream.Write(data)
		if err != nil {
			t.Fatal(err)
		}
	}

	serverDone.Wait()

	wantBytes := count * (4*repeat + 2)
	if n := clientTx.Len(); n != wantBytes {
		t.Errorf("expected %d got %d bytes in sent buffer", wantBytes, n)
	}
	if n := serverBidiRx.Len(); n != wantBytes {
		t.Errorf("expected %d got %d bytes in receive buffer of bidirectional stream", wantBytes, n)
	}
	if n := serverUnidiRx.Len(); n != wantBytes {
		t.Errorf("expected %d got %d bytes in receive buffer of unidirectional stream", wantBytes, n)
	}
	if nTx, nRx := clientTx.Len(), serverBidiRx.Len(); nTx != nRx {
		diff := nTx - nRx
		t.Errorf("tx(%d) and rx(%d) buffers not equal (diff: %d) in bidirectional stream", nTx, nRx, diff)
		assert.Equal(t, clientTx.Bytes(), serverBidiRx.Bytes())
	}
	if nTx, nRx := clientTx.Len(), serverUnidiRx.Len(); nTx != nRx {
		diff := nTx - nRx
		t.Errorf("tx(%d) and rx(%d) buffers not equal (diff: %d) in unidirectional stream", nTx, nRx, diff)
		assert.Equal(t, clientTx.Bytes(), serverUnidiRx.Bytes())
	}

	if clientBidiRx.Len() != 0 {
		t.Errorf("client received data from bidirectional stream although nothing was sent")
	}

	err = ta.Stop(TransportStopInfo{})
	if err != nil {
		t.Fatal(err)
	}

	err = tb.Stop(TransportStopInfo{})
	if err != nil {
		t.Fatal(err)
	}

	clientDone.Wait()
	assert.NoError(t, lisClose.Close())
}

func readBidiLoop(t *testing.T, s *BidirectionalStream, buf io.Writer, done *sync.WaitGroup) {
	defer done.Done()
	bufSz := 1024
	buffer := make([]byte, bufSz)
	for {
		res, err := s.ReadInto(buffer)
		_, werr := buf.Write(buffer[:res.Amount])
		assert.NoError(t, werr, "buffer.Write never failes(?)")
		if err != nil || res.Finished {
			return
		}
		buffer = buffer[:bufSz]
	}
}

func readUnidiLoop(t *testing.T, s *ReadableStream, buf io.Writer, done *sync.WaitGroup) {
	defer done.Done()
	bufSz := 1024
	buffer := make([]byte, bufSz)
	for {
		res, err := s.ReadInto(buffer)
		_, werr := buf.Write(buffer[:res.Amount])
		assert.NoError(t, werr, "buffer.Write never failes(?)")
		if err != nil || res.Finished {
			return
		}
		buffer = buffer[:bufSz]
	}
}

// GenerateSelfSigned creates a self-signed certificate
func GenerateSelfSigned() (*x509.Certificate, crypto.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	origin := make([]byte, 16)

	// Max random value, a 130-bits integer, i.e 2^130 - 1
	maxBigInt := new(big.Int)
	/* #nosec */
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	serialNumber, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotAfter:              time.Now().AddDate(0, 1, 0),
		SerialNumber:          serialNumber,
		Version:               2,
		Subject:               pkix.Name{CommonName: hex.EncodeToString(origin)},
		IsCA:                  true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}
