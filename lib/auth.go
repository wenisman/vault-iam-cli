package lib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/spf13/viper"
)

// HttpClient - interface to provide members a way of injecting requirements for testing
type HttpClient interface {
	Get(string) (*http.Response, error)
	Post(url string, contentType string, body io.Reader) (*http.Response, error)
	Do(*http.Request) (*http.Response, error)
}

func extractClientToken(input []byte) (string, error) {
	var temp map[string]interface{}
	err := json.Unmarshal(input, &temp)
	if err != nil {
		return "", err
	}

	auth := temp["auth"].(map[string]interface{})
	return auth["client_token"].(string), nil
}

func extractJwt(input []byte) (string, error) {
	var temp map[string]interface{}
	err := json.Unmarshal(input, &temp)
	if err != nil {
		return "", err
	}

	data := temp["data"].(map[string]interface{})
	return data["ClientToken"].(string), nil
}

// AWSLogin - call vault with AWS data to log in and gain the client token
func AWSLogin(client HttpClient, iamData IamData) (string, error) {
	// basic configuration options - read from viper
	vaultURL := viper.Get("vault-url")
	iamString, _ := json.Marshal(iamData)
	buf := bytes.NewBuffer(iamString)
	resp, err := client.Post(fmt.Sprintf("%s/v1/auth/aws/login", vaultURL), "application/json", buf)
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Unable to retrieve IAM Login from vault: %s", body)
	}

	return extractClientToken(body)
}

// GetJWT - call vault get jwt with the role and option claim
func GetJWT(client HttpClient, clientToken string, roleName string, claimName string) (string, error) {
	log.Println("client token:", clientToken)
	// construct the JSON to send to vault
	data := map[string]interface{}{
		"role_name": roleName,
	}

	if claimName != "" {
		data["claim_name"] = claimName
	}

	b, _ := json.Marshal(data)
	buf := bytes.NewReader(b)

	// construct the request to send
	vaultURL := viper.Get("vault-url")
	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/v1/auth/jwtplugin/token/issue", vaultURL), buf)
	req.Header.Add("X-Vault-Token", clientToken)
	req.Header.Add("Content-Type", "application/json")

	//	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	// extract the jwt from the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Unable to retrieve JWT : %s", body)
	}

	return extractJwt(body)
}
