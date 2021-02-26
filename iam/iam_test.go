package iam

import (
	"context"
	"testing"

	_ "github.com/go-kivik/couchdb/v4"
	"github.com/go-kivik/kivik/v4"
)

func TestIAM(t *testing.T) {
	iam := &IAMAuthenticator{
		apiKey: "",
		token:  iamToken{},
	}

	t.Run("Test register", func(t *testing.T) {
		client, err := kivik.New("couch", "http://example.com")
		if err != nil {
			t.Error(err)
		}

		err = client.Authenticate(context.TODO(), iam)
		if err != nil {
			t.Error(err)
		}
	})

}
