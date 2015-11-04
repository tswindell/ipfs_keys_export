package main

import (
    proto "github.com/golang/protobuf/proto"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "bufio"
    "fmt"
    "os"
)

func main() {
    showError := func(m string, e error) {
      fmt.Fprintln(os.Stderr, m, e.Error());
    }

    reader := bufio.NewReader(os.Stdin);
    input, _ := reader.ReadString('\n');

    data, e := base64.StdEncoding.DecodeString(input);
    if e != nil {
        showError("Unable to decode base64 input: %s", e);
        return;
    }

    pk := new(PrivateKey);
    e = proto.Unmarshal(data, pk);
    if e != nil {
        showError("Unable to unmarshal protobuf data: %s", e);
        return;
    }

    sk, e := x509.ParsePKCS1PrivateKey(pk.GetData())
    if  e != nil {
        showError("Failed to parse key: %s", e);
        return;
    }

    e = sk.Validate();
    if  e != nil {
        showError("Key validation failed: %s", e);
        return;
    }

    sk_der := x509.MarshalPKCS1PrivateKey(sk);
    sk_blk := pem.Block {
        Type: "RSA PRIVATE KEY",
        Headers: nil,
        Bytes: sk_der,
    };
    sk_pem := string(pem.EncodeToMemory(&sk_blk));

    fmt.Printf(sk_pem);
}

