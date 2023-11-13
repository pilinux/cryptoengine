# cryptoengine

This simplifies even further the usage of the NaCl crypto primitives,
by taking care of the `nonce` part.
It uses a KDF, specifically HKDF to compute the nonces.

## Current Status

![Build](https://github.com/pilinux/cryptoengine/actions/workflows/go.yml/badge.svg)
![Linter](https://github.com/pilinux/cryptoengine/actions/workflows/golangci-lint.yml/badge.svg)
![CodeQL](https://github.com/pilinux/cryptoengine/actions/workflows/codeql.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/pilinux/cryptoengine)](https://goreportcard.com/report/github.com/pilinux/cryptoengine)
[![Go Reference](https://pkg.go.dev/badge/github.com/pilinux/cryptoengine.svg)](https://pkg.go.dev/github.com/pilinux/cryptoengine)

- Forked from [sec51/cryptoengine](https://github.com/sec51/cryptoengine)
- Actively maintained, updates will be released under [pilinux/cryptoengine](https://github.com/pilinux/cryptoengine)

## Big Picture

The encryption and decryption phases are the following:

```text
Message -> Encrypt -> EncryptedMessage -> ToBytes() -> < = NETWORK = >  <- FromBytes() -> EncryptedMessage -> Decrypt -> Message
```

## Usage

- 1. Import the library

  ```go
  import github.com/pilinux/cryptoengine
  ```

- 2. Instantiate the `CryptoEngine` object via:

  ```go
  engine, err := cryptoengine.InitCryptoEngine("Sec51")
  if err != nil {
    return err
  }
  ```

See the go doc for more info about the InitCryptoEngine parameter

- 3. Encrypt a message using symmetric encryption

  ```go
  message := "the quick brown fox jumps over the lazy dog"
  engine.NewMessage(message)
  if err != nil {
    return err
  }
  ```

- 4. Serialize the message to a byte slice, so that it can be safely sent to the network

  ```go
  messageBytes, err := tcp.ToBytes()
  if err != nil {
    t.Fatal(err)
  }
  ```

- 5. Parse the byte slice back to a message

```go
  message, err := MessageFromBytes(messageBytes)
  if err != nil {
    t.Fatal(err)
  }
  ```

## License

Copyright (c) 2015 Sec51.com <info@sec51.com>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
