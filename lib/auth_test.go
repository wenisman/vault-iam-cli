package lib

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/spf13/viper"
)

// MockAwsHTTPClient - mocked out client for testing the http connection to aws
type MockAwsHTTPClient struct{}

func (m *MockAwsHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return nil, nil
}

func (m *MockAwsHTTPClient) Get(string) (*http.Response, error) {
	return nil, nil
}

func (m *MockAwsHTTPClient) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	resp := &http.Response{
		Body:       ioutil.NopCloser(bytes.NewBuffer([]byte("{ \"auth\": { \"client_token\":\"some-token-guid\" } }"))),
		StatusCode: 200,
	}

	return resp, nil
}

func TestAwsLogin(t *testing.T) {
	viper.Set("vault-url", "")
	iam := IamData{
		RequestURL:        "sample url",
		HTTPRequestMethod: "sample method",
		RequestBody:       "sample body",
		RequestHeaders:    "sample headers",
	}

	httpClient := &MockAwsHTTPClient{}
	clientToken, err := AWSLogin(httpClient, iam)

	if err != nil {
		t.Fatalf("unable to log in using AWS: %#v", err)
	}

	if clientToken != "some-token-guid" {
		t.Fatalf("Incorrect client token returned")
	}
	//resp, _ := GetJWT(httpClient, "clienttoken", "role", "claim")
}
