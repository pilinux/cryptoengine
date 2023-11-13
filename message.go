package cryptoengine

import (
	"bytes"
	"errors"

	"github.com/sec51/convert/smallendian"
)

// Message struct encapsulates the encrypted message in a TCP packet, in an easily parsable format.
// We assume the data is always encrypted.
//
// Format:
//
// |version| => 8 bytes (uint64 total message length)
//
// |type| 	 => 4 bytes (int message version)
//
// |message| => N bytes ([]byte message)
type Message struct {
	Version int    // version of the message, done to support backward compatibility
	Type    int    // message type - this can be used on the receiver part to process different types
	Text    string // the encrypted message
}

// EncryptedMessage struct represent the encrypted message which can be sent over the network safely.
//
// |length| => 8 bytes (uint64 total message length)
//
// |nonce| => 24 bytes ([]byte size)
//
// |message| => N bytes ([]byte message)
type EncryptedMessage struct {
	length uint64
	nonce  [nonceSize]byte
	data   []byte
}

// NewMessage creates a new message with a clear text and the message type.
//
// messageType: is an identifier to distinguish the messages on the receiver and parse them
//
// for example if zero is a JSON message and 1 is XML, then the received can parse different formats with different methods
func NewMessage(clearText string, messageType int) (Message, error) {
	m := Message{}
	if clearText == "" {
		return m, errors.New("clear text cannot be empty")
	}

	m.Text = clearText //:= message{tcpVersion, messageType, clearText}
	m.Type = messageType
	m.Version = tcpVersion
	return m, nil
}

func (m Message) toBytes() []byte {
	var buffer bytes.Buffer

	// version
	versionBytes := smallendian.ToInt(m.Version)
	buffer.Write(versionBytes[:])

	// type
	typeBytes := smallendian.ToInt(m.Type)
	buffer.Write(typeBytes[:])

	// message
	buffer.WriteString(m.Text)

	return buffer.Bytes()
}

// Parse the bytes coming from the network and extract
//
// |length| => 8
//
// |nonce|	=> nonce size
//
// |message| => message
func encryptedMessageFromBytes(data []byte) (EncryptedMessage, error) {
	var err error
	var lengthData [8]byte
	var nonceData [nonceSize]byte
	minimumDataSize := 8 + nonceSize
	m := EncryptedMessage{}

	// check if the data is smaller than 36 which is the minimum
	if data == nil {
		return m, ErrorMessageParsing
	}

	if len(data) < minimumDataSize+1 {
		return m, ErrorMessageParsing
	}

	length := data[:8]
	nonce := data[8 : 8+nonceSize] // 24 bytes
	message := data[minimumDataSize:]

	total := copy(lengthData[:], length)
	if total != 8 {
		return m, ErrorMessageParsing
	}

	total = copy(nonceData[:], nonce)
	if total != nonceSize {
		return m, ErrorMessageParsing
	}

	m.length = smallendian.FromUint64(lengthData)
	m.nonce = nonceData
	m.data = message
	return m, err
}

// This function separates the associated data once decrypted
func messageFromBytes(data []byte) (*Message, error) {
	var err error
	var versionData [4]byte
	var typeData [4]byte
	minimumDataSize := 4 + 4
	m := new(Message)

	// check if the data is smaller than 36 which is the minimum
	if data == nil {
		return nil, ErrorMessageParsing
	}

	if len(data) < minimumDataSize+1 {
		return nil, ErrorMessageParsing
	}

	version := data[:4]
	typeMsg := data[4:8]
	message := data[8:]

	total := copy(versionData[:], version)
	if total != 4 {
		return nil, ErrorMessageParsing
	}

	total = copy(typeData[:], typeMsg)
	if total != 4 {
		return nil, ErrorMessageParsing
	}

	m.Version = smallendian.FromInt(versionData)
	m.Type = smallendian.FromInt(typeData)
	m.Text = string(message)
	return m, err
}

// ToBytes converts the encrypted message to bytes
//
// # STRUCTURE
//
// 8  => |SIZE|
//
// 24 => |NONCE|
//
// N  => |DATA|
//
// |size| => 8 bytes (uint64 total message length)
//
// |type| 	 => 4 bytes (int message version)
//
// |message| => N bytes ([]byte message)
func (m EncryptedMessage) ToBytes() ([]byte, error) {
	var buffer bytes.Buffer

	// length
	lengthBytes := smallendian.ToUint64(m.length)
	buffer.Write(lengthBytes[:])

	// nonce
	buffer.Write(m.nonce[:])

	// message
	buffer.Write(m.data)

	return buffer.Bytes(), nil
}
