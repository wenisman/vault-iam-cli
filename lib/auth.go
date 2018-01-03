package lib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/spf13/viper"
)

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
	return data["token"].(string), nil
}

// AWSLogin - call vault with AWS data to log in and gain the client token
func AWSLogin() (string, error) {
	// basic configuration options - read from viper
	vaultURL := viper.Get("vault_url")

	iamData, err := GenerateLoginData()
	if err != nil {
		return "", err
	}

	iamString, _ := json.Marshal(iamData)
	buf := bytes.NewBuffer(iamString)
	resp, err := http.Post(fmt.Sprintf("%s/v1/auth/aws/login", vaultURL), "application/json", buf)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return extractClientToken(body)
}

// GetJWT - call vault get jwt with the role and option claim
func GetJWT(clientToken string, roleName string, claimName string) (string, error) {
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
	vaultURL := viper.Get("vault_url")
	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/v1/auth/jwtplugin/token/issue", vaultURL), buf)
	req.Header.Add("X-Vault-Token", clientToken)
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	// extract the jwt from the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return extractJwt(body)
}
