package iam

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/go-kivik/couchdb/v4/chttp"
)

const (
	ibmIAMEndpoint = "https://iam.cloud.ibm.com/identity/token"
)

type IAMToken struct {
	AccessToken string `json:"access_token"`
	Expiration  int64  `json:"expiration"`
}

type IAMAuthenticator struct {
	Username string
	Password string

	apiKey string
	token  IAMToken

	transport http.RoundTripper
}

// Apperently this makes it inplement http.RoundTripper which kivik couchdb recognizes and then calls this every request
func (iam *IAMAuthenticator) RoundTrip(req *http.Request) (*http.Response, error) {

	// if the token expires in 5min or less get a new one
	// TODO: on high requests this will cause a bunch of parallel token refreshes so somehow prevent that
	if iam.token.Expiration-300 <= time.Now().Unix() {
		token, err := getIAMToken(iam.apiKey)
		if err != nil {
			return nil, err
		}

		iam.token = token

	}

	req.Header.Add("Authorization", "Bearer "+iam.token.AccessToken)
	return iam.transport.RoundTrip(req)
}

// This is copy pasted from the BasicAuth Authenticator that comes with kivik/CouchDB
func (iam *IAMAuthenticator) Authenticate(c *chttp.Client) error {
	iam.transport = c.Transport
	if iam.transport == nil {
		iam.transport = http.DefaultTransport
	}
	c.Transport = iam
	return nil
}

func NewIAMAuthenticator(apiKey string) (*IAMAuthenticator, error) {
	token, err := getIAMToken(apiKey)
	if err != nil {
		return nil, err
	}

	return &IAMAuthenticator{
		apiKey: apiKey,
		token:  token,
	}, nil
}

func getIAMToken(token string) (IAMToken, error) {
	iamToken := IAMToken{}

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
