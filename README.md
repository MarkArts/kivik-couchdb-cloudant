# Kivik Couchdb Cloudant Authenticator
This package provides a basic implementation of the

## How to use
```golang

import (
  _ "github.com/go-kivik/couchdb/v4"
  "github.com/go-kivik/kivik/v4"
  iam "github.com/MarkArts/kivik-couchdb-cloudant/authenticator"
)

func main(){
  fmt.PrintLhn(setup())
}

func setup() error {
  client, err := kivik.New("couch", cloudantDSN)
  if err != nil {
    return nil, err
  }

  iamAuthenticator, err := iam.NewIAMAuthenticator(apiKey)
  if err != nil {
    return nil, err
  }

  err = client.Authenticate(context.TODO(), iamAuthenticator)
  if err != nil {
    return nil, err
  }
}

```

## Limitations
### Replication
Most likely using kivik's replication functions won't work as Cloudant replication works with a different auth mechanism.

### Refresh tokens
This lib doesn't use the refresh tokens as they are only valid for a month which means your app won't be able to run longer then a month without restart.