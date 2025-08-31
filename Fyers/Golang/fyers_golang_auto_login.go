package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/pquerna/otp/totp"
)

// User Login Credinatils
var fyers_id string = "AC000000" // Replace with your Fyers ID
// How to get TOTP Key Follow this video : https://youtu.be/l1ylbSavzNU?si=mxlkmzkecF0dNq_W
var totp_secert_key string = "your_totp_key" // Replace with your TOTP Key
var userPin string = "your_user_pin"         // User pin for fyers account

// App Sepecfic Credinatils
// How to get App ID and App Secert Follow this video : https://youtu.be/q1H8fO34EQc?si=gkLxECggWLkMhoAa
var app_type string = "100"
var app_id string = "your_app_id_without_app_type" // App ID from myapi dashboard is in the form appId-appType. Example - EGNI8CE27Q-100, In this code EGNI8CE27Q will be app_id and 100 will be the app_type
var app_secert string = "your_app_secret"          // # App secret from myapi dashboard
var redirect_url string = "https://trade.fyers.in/api-login/redirect-uri/index.html"

// ######################################################################################
// HardCoded Values : Don't Touch this Part
var app_id_type string = "2"

//######################################################################################

// #####################################################################################
// EndPoints : Don't Touch this Part
var baseURl string = "https://api-t2.fyers.in/vagator/v2"
var sendLoginOTPUrl = baseURl + "/send_login_otp"
var verifyOTPUrl = baseURl + "/verify_otp"
var verifyPinURl = baseURl + "/verify_pin"
var baseURlTwo string = "https://api-t1.fyers.in/api/v3"
var urlTokenUrl = baseURlTwo + "/token"
var validateAuthCodeURL = baseURlTwo + "/validate-authcode"

// #####################################################################################

type ResponseVerifyPIN struct {
	Status  string `json:"s"`
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		RefreshToken string `json:"refresh_token"`
		AccessToken  string `json:"access_token"`
	} `json:"data"`
}

// send_login_otp sends a login OTP request to the Fyers API
// It takes no arguments and returns a string containing the request_key
// and an error if any
func send_login_otp() (string, error) {
	// payload is the JSON payload to send to the API
	// It contains the fyers_id and the app_id
	payload := `{"fy_id":"` + fyers_id + `","app_id":"` + app_id_type + `"}`

	// jsonStr is the JSON payload converted to a byte slice
	var jsonStr = []byte(payload)

	// req is the HTTP POST request to send to the API
	req, _ := http.NewRequest("POST", sendLoginOTPUrl, bytes.NewBuffer(jsonStr))

	// client is the HTTP client to use
	client := &http.Client{}

	// resp is the response from the API
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// body is the response body
	body, _ := io.ReadAll(resp.Body)

	// jsonMap is the JSON response converted to a map of strings
	jsonMap := make(map[string]string)
	json.Unmarshal(body, &jsonMap)

	// request_key is the request key from the response
	request_key := jsonMap["request_key"]
	return request_key, nil
}

// generateTOTP generates a TOTP code using the given secret key.
// It takes a secret key as a string and returns a string containing the TOTP code
// and an error if any
func generateTOTP(secret string) (string, error) {
	// Generate a TOTP using the given secret key
	otp, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("error generating TOTP: %w", err)
	}

	// Return the TOTP code
	return otp, nil
}

// generateSHA256 takes an input string and returns its SHA-256 hash in hex format.
// It takes a string as an argument and returns a string containing the
// SHA-256 hash of the input string in hex format.
func generateSHA256(input string) string {
	// Calculate the SHA-256 hash of the input string
	hash := sha256.Sum256([]byte(input)) // returns [32]byte

	// Convert the hash to a hex string
	return hex.EncodeToString(hash[:]) // convert to hex string
}

// verify_TOTP verifies a TOTP code using the given request_key and TOTP code.
// It takes a request_key and a TOTP code as strings and returns a string containing
// the new request_key and an error if any.
func verify_TOTP(request_key string, totp string) (string, error) {
	// payload is the JSON payload to send to the API
	// It contains the request_key and the TOTP code
	payload := `{"request_key":"` + request_key + `","otp":"` + totp + `"}`

	// jsonStr1 is the JSON payload converted to a byte slice
	jsonStr1 := []byte(payload)
	req, _ := http.NewRequest("POST", verifyOTPUrl, bytes.NewBuffer(jsonStr1))

	// client is the HTTP client to use
	client := &http.Client{}

	// resp is the response from the API
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error verifying TOTP: %w", err)
	}
	defer resp.Body.Close()

	// body is the response body
	body, _ := io.ReadAll(resp.Body)

	// jsonMap is the JSON response converted to a map of strings
	jsonMap := make(map[string]string)
	json.Unmarshal(body, &jsonMap)

	// newRequestKey is the new request_key from the response
	newRequestKey := jsonMap["request_key"]

	// Return the new request_key
	return newRequestKey, nil
}

// verify_PIN verifies a PIN using the given request_key.
// It takes a request_key as a string and returns a string containing
// the access token and an error if any.
func verify_PIN(request_key string) (string, error) {

	// payload is the JSON payload to send to the API
	// It contains the request_key and the PIN
	payload := `{"request_key":"` + request_key + `", "identity_type": "pin","identifier":"` + userPin + `"}`

	// jsonStr1 is the JSON payload converted to a byte slice
	jsonStr1 := []byte(payload)
	req, _ := http.NewRequest("POST", verifyPinURl, bytes.NewBuffer(jsonStr1))

	// client is the HTTP client to use
	client := &http.Client{}

	// resp is the response from the API
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error verifying PIN: %w", err)
	}
	defer resp.Body.Close()

	// body is the response body
	body, _ := io.ReadAll(resp.Body)

	// response is the JSON response converted to a ResponseVerifyPIN struct
	var response ResponseVerifyPIN
	json.Unmarshal(body, &response)

	// accessToken is the access token from the response
	accessToken := response.Data.AccessToken

	// Return the access token
	return accessToken, nil
}

// parsingURL parses a given URL and returns the value of the "auth_code" parameter.
// It takes a raw URL as a string and returns the value of the "auth_code" parameter
// as a string and an error if any.
func parsingURL(rawValue string) (string, error) {

	// rawURL is the URL to parse
	rawURL := rawValue

	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	// Get the value of the auth_code parameter
	authCode := parsedURL.Query().Get("auth_code")

	// Return the value of the auth_code parameter
	return authCode, nil
}

// authCode generates an authorization code using the given access token.
// It takes an access token as a string and returns the generated authorization
// code as a string and an error if any.
func authCode(accessToken string) (string, error) {
	// payload is the JSON payload to send to the API
	// It contains the fyers_id, app_id, redirect_uri, appType, and other parameters
	// required for generating an authorization code
	payload := `{"fyers_id":"` + fyers_id + `","app_id":"` + app_id + `","redirect_uri":"` + redirect_url + `","appType":"` + app_type + `","code_challenge":"","state": "sample_state","scope": "","nonce": "","response_type": "code","create_cookie": "True"}`

	// jsonStr is the JSON payload converted to a byte slice
	jsonStr := []byte(payload)

	// req is the HTTP request to send to the API
	// It contains the Authorization header with the given access token
	req, _ := http.NewRequest("POST", urlTokenUrl, bytes.NewBuffer(jsonStr))
	value := `Bearer ` + accessToken
	req.Header.Set("Authorization", value)
	req.Header.Set("Content-Type", "application/json")

	// client is the HTTP client to use
	client := &http.Client{}

	// resp is the response from the API
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error generating authorization code: %w", err)
	}
	defer resp.Body.Close()

	// body is the response body
	body, _ := io.ReadAll(resp.Body)

	// jsonMap is the JSON response converted to a map of strings
	jsonMap := make(map[string]string)
	json.Unmarshal(body, &jsonMap)

	// url is the URL from the response
	url := jsonMap["Url"]

	// authCode is the authorization code from the URL
	authCode, err := parsingURL(url)

	if err != nil {
		return "", fmt.Errorf("error parsing URL: %w", err)
	}

	// Return the authorization code
	return authCode, nil
}

// generatingAccessToken generates an access token from the given authorization code
//
// It takes an authorization code as a string and returns a string containing the
// access token and an error if any
func generatingAccessToken(authCode string) (string, error) {
	// input is the string which will be used to generate the SHA256 hash
	// It is in the format of "app_id-app_type:app_secret"
	input := fmt.Sprintf("%s-%s:%s", app_id, app_type, app_secert)
	// appIDHash is the SHA256 hash of the input string
	appIDHash := generateSHA256(input)
	// payload is the JSON payload to send to the API
	// It contains the grant type, app ID hash, and authorization code
	payload := `{"grant_type":"authorization_code","appIdHash":"` + appIDHash + `","code":"` + authCode + `"}`

	jsonStr := []byte(payload)
	// req is the HTTP request to send to the API
	// It contains the JSON payload and the Content-Type header set to "application/json"
	req, _ := http.NewRequest("POST", validateAuthCodeURL, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	// client is the HTTP client to use
	client := &http.Client{}

	// resp is the response from the API
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// body is the response body
	body, _ := io.ReadAll(resp.Body)

	// jsonMap is the JSON response converted to a map of strings
	jsonMap := make(map[string]string)
	json.Unmarshal(body, &jsonMap)

	// accessToken is the access token from the response
	accessToken := jsonMap["access_token"]

	return accessToken, nil
}

// dumpingIntoFile writes the access token and authorization code to a JSON file.
// The filename will be the fyers_id followed by ".json".
// The JSON file will contain the current date, app_id, app_id_with_app_type, access_token,
// access_token_with_APPID.
func dumpingIntoFile(access_token string) {

	detailsMap := make(map[string]string)

	// First entry will be today date in the Map
	currentTime := time.Now()
	currentDate := currentTime.Format("2006-01-02")
	detailsMap["Date"] = currentDate

	detailsMap["app_id"] = app_id
	detailsMap["app_id_with_app_type"] = app_id + `-` + app_type
	detailsMap["access_token"] = access_token
	detailsMap["access_token_with_APPID"] = app_id + `-` + app_type + `:` + access_token
	// detailsMap["authorization"] = authoirzation

	jsonData, err := json.MarshalIndent(detailsMap, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling map:", err)
		return
	}

	// Write JSON data to a file
	fileName := fyers_id + `.json`

	err = ioutil.WriteFile(fileName, jsonData, 0644)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
}

// main is the entry point of the program.
func main() {

	// Step 1: Send OTP
	// Send OTP and get the request_key
	request_key, err := send_login_otp()

	if err != nil {
		fmt.Println("Error while sending OTP")
		panic(err)
	}

	fmt.Println("\nRequest key is ", request_key)

	// Step 2: Generate TOTP
	// Generate TOTP using the secret key
	totp, err := generateTOTP(totp_secert_key)

	if err != nil {
		fmt.Println("Error while OTP generating")
		panic(err)
	}

	fmt.Println("\nOtp is ", totp)

	// Step 3: Verify TOTP
	// Verify the TOTP with the request_key
	new_request_key, err := verify_TOTP(request_key, totp)

	if err != nil {
		fmt.Println("Error while Verfiying TOTP")
		panic(err)
	}

	fmt.Println("\nNew Request key is ", new_request_key)

	// Step 4: Verify PIN
	// Verify the user's PIN
	access_token, err := verify_PIN(new_request_key)

	if err != nil {
		fmt.Println("Error while verifiying PIN ")
		panic(err)
	}

	fmt.Println("\nAccesstoken ", access_token)

	// Step 5: Generate auth code
	// Generate the auth code using the access token
	authCode, err := authCode(access_token)

	if err != nil {
		fmt.Println("Error while generating authcode")
		panic(err)
	}
	fmt.Println("\nAuth code is ", authCode)

	// Step 6: Generate the final access token
	// Generate the final access token using the auth code
	final_access_token, err := generatingAccessToken(authCode)

	if err != nil {
		fmt.Println("Error while generating acces token")
		panic(err)
	}
	fmt.Println("\nFinal Access token is ", final_access_token)

	// Step 7: Dump data to a file
	// Dump the access token to a JSON file
	dumpingIntoFile(final_access_token)
}
