package authenticator

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/go-kivik/couchdb/v4/chttp"
)

const (
	ibmIAMEndpoint            = "https://iam.cloud.ibm.com/identity/token"
	refreshTokenCheckInterval = time.Minute * 5
)

type iamToken struct {
	AccessToken string `json:"access_token"`
	Expiration  int64  `json:"expiration"`
}

// IAMAuthenticator implements couchdb chttp Auhtenticator and allows kivik/couchdb to connect with cloudant
// example:
// ```
//	client, err := kivik.New("couch", dsn)
//	if err != nil {
// 		return nil, err
//	}
//
// 	iamAuthenticator, err := NewIAMAuthenticator(apiKey)
// 	if err != nil {
//		return nil, err
// 	}
//
//	err = client.Authenticate(context.TODO(), iamAuthenticator)
//	if err != nil {
//		return nil, err
//	}
// ```
type IAMAuthenticator struct {
	Username string
	Password string

	apiKey string
	token  iamToken

	transport http.RoundTripper
}

// RoundTrip implements http.RoundTripper which kivik couchdb recognizes and then calls this every request
// When a refresh is needed this will trigger a token refresh which on failure will
// throw a async panic and will clear the current token making the next request error on permissions
func (iam *IAMAuthenticator) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", "Bearer "+iam.token.AccessToken)
	return iam.transport.RoundTrip(req)
}

// Authenticate This is copy pasted from the BasicAuth Authenticator that comes with kivik/CouchDB
func (iam *IAMAuthenticator) Authenticate(c *chttp.Client) error {
	iam.transport = c.Transport
	if iam.transport == nil {
		iam.transport = http.DefaultTransport
	}
	c.Transport = iam
	return nil
}

func (iam *IAMAuthenticator) refreshToken() error {
	token, err := getIAMToken(iam.apiKey)
	if err != nil {
		return err
	}

	iam.token = token

	return nil
}

// NewIAMAuthenticator return a IAMAuthenticator with a fetched token
func NewIAMAuthenticator(apiKey string) (*IAMAuthenticator, error) {
	token, err := getIAMToken(apiKey)
	if err != nil {
		return nil, err
	}

	iam := &IAMAuthenticator{
		apiKey: apiKey,
		token:  token,
	}

	go func() {
		for {
			if iam.token.Expiration-300 <= time.Now().Unix() {
				err := iam.refreshToken()
				if err != nil {
					panic(err)
				}
			}
			time.Sleep(refreshTokenCheckInterval)
		}
	}()

	return iam, nil
}

func getIAMToken(token string) (iamToken, error) {
	iamToken := iamToken{}

	resp, err := http.PostForm(ibmIAMEndpoint,
		url.Values{
			"apikey":     {token},
			"grant_type": {"urn:ibm:params:oauth:grant-type:apikey"},
		},
	)
	if err != nil {
		return iamToken, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return iamToken, err
	}

	err = json.Unmarshal(body, &iamToken)
	if err != nil {
		return iamToken, err
	}

	return iamToken, nil
}
