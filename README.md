# go-phpencryption
This package implements https://github.com/defuse/php-encryption which is used in league/oauth2-server in PHP.

## How to use
Add the package to your project:
```bash
go get github.com/alirasoli/go-phpencryption
```

```go
package main

import (
	"fmt"
	"log"

	"github.com/alirasoli/go-phpencryption"
)

const encryptionKey = "key"
const data = "datatoencrypt"

func main() {
	p := phpencryption.NewPHPEncryption([]byte(encryptionKey))
	
	encrypted, err := p.Encrypt([]byte(data))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(encrypted)

	decrypted, err := p.Decrypt(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(decrypted))
}

```