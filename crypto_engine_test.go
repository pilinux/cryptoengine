package cryptoengine

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestSecretKeyEncryption(t *testing.T) {

	message, err := NewMessage("The quick brown fox jumps over the lazy dog", 1)
	if err != nil {
		t.Fatal(err)
	}

	enginePeer, err := InitCryptoEngine("Sec51")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	engine, err := InitCryptoEngine("Sec51")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	encryptedMessage, err := engine.NewEncryptedMessage(message)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	messageBytes, err := encryptedMessage.ToBytes()
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// temporary write the corpus for fuzzing
	// writeFile("corpus/4", messageBytes)

	// simulate writing to network
	var buffer bytes.Buffer
	buffer.Write(messageBytes)

	// read the bytes back
	storedData, err := io.ReadAll(&buffer)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// parse the bytes
	storedMessage, err := encryptedMessageFromBytes(storedData)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// check the encrypted message data if it matches
	if storedMessage.length != encryptedMessage.length {
		t.Error("Encrypted Message length mismacth")
	}

	if !bytes.Equal(storedMessage.nonce[:], encryptedMessage.nonce[:]) {
		t.Error("Encrypted  Message nonce mismacth")
	}

	if !bytes.Equal(storedMessage.data[:], encryptedMessage.data[:]) {
		t.Error("Encrypted Message data mismacth")
	}

	decrypted, err := enginePeer.Decrypt(messageBytes)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	if decrypted.Type != message.Type {
		cleanUp()
		t.Fatal("Secret key encryption/decryption broken")
	}

	if decrypted.Version != message.Version {
		cleanUp()
		t.Fatal("Secret key encryption/decryption broken")
	}

	if decrypted.Text != message.Text {
		cleanUp()
		t.Fatal("Secret key encryption/decryption broken")
	}
}

func TestPublicKeyEncryption(t *testing.T) {
	message, err := NewMessage("The quick brown fox jumps over the lazy dog", 1)
	if err != nil {
		t.Fatal(err)
	}

	firstEngine, err := InitCryptoEngine("Sec51Peer1")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}
	// test the verification engine
	firstVerificationEngine, err := NewVerificationEngine("Sec51Peer1")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	secondEngine, err := InitCryptoEngine("Sec51Peer2")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}
	// test the verification engine
	secondVerificationEngine, err := NewVerificationEngine("Sec51Peer2")
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	encryptedMessage, err := firstEngine.NewEncryptedMessageWithPubKey(message, secondVerificationEngine)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	messageBytes, err := encryptedMessage.ToBytes()
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// temporary write the corpus for fuzzing
	// writeFile("corpus/5", messageBytes)

	// simulate writing to network
	var buffer bytes.Buffer
	buffer.Write(messageBytes)

	// read the bytes back
	storedData, err := io.ReadAll(&buffer)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// parse the bytes
	storedMessage, err := encryptedMessageFromBytes(storedData)
	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	// check the encrypted message data if it matches
	if storedMessage.length != encryptedMessage.length {
		t.Error("Encrypted Message length mismacth")
	}

	if !bytes.Equal(storedMessage.nonce[:], encryptedMessage.nonce[:]) {
		t.Error("Encrypted  Message nonce mismacth")
	}

	if !bytes.Equal(storedMessage.data[:], encryptedMessage.data[:]) {
		t.Error("Encrypted Message data mismacth")
	}

	decrypted, err := secondEngine.DecryptWithPublicKey(storedData, firstVerificationEngine)

	if err != nil {
		cleanUp()
		t.Fatal(err)
	}

	if decrypted.Version != message.Version {
		cleanUp()
		t.Fatal("Public key encryption/decryption broken")
	}

	if decrypted.Type != message.Type {
		cleanUp()
		t.Fatal("Public key encryption/decryption broken")
	}

	if decrypted.Text != message.Text {
		cleanUp()
		t.Fatal("Public key encryption/decryption broken")
	}

}

func TestSanitization(t *testing.T) {

	id := "S E C	51"

	sanitized := sanitizeIdentifier(id)
	if strings.Contains(sanitized, " ") {
		t.Error("The sanitization function does not remove spaces")
	}

	if strings.Contains(sanitized, "\t") {
		t.Error("The sanitization function does not remove tabs")
	}

}

func cleanUp() {
	//removeFolder(keyPath)
}
