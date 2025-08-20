package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// Client Info (ENTER YOUR OWN INFO HERE!! Data varies from users and app types)
var (
	UserID   = "your_userId"
	PassWord = "your_password"
	// NOTE : For TOTP You can check this video : https://www.youtube.com/watch?v=O-i-Qnh_oG0
	TOTP_KEY = "your_totp_key"
)

// NOTE : For APPID and APP_SECRET You can check this video : https://www.youtube.com/watch?v=MDTbhNnHCck&ab_channel=PankajSaini
// App Level Configuration : This APP ID and APP_SECRET you will get from developer portal of Zerodha
var (
	APP_ID     = "appId"
	APP_SECRET = "appSecert"
)

// API endpoints
var (
	BASE_URL_LOGIN = "https://kite.zerodha.com/api/login"

	SUCCESS = 1
	ERROR   = -1
)

type LoginResponse struct {
	Status string `json:"status"`
	Data   struct {
		UserID    string `json:"user_id"`
		RequestID string `json:"request_id"`
	} `json:"data"`
}

type zerodhaAuthVerifyResponse struct {
	Status string `json:"status"`
	Data   *struct {
		UserType      string   `json:"user_type"`
		Email         string   `json:"email"`
		UserName      string   `json:"user_name"`
		UserShortname string   `json:"user_shortname"`
		Broker        string   `json:"broker"`
		Exchanges     []string `json:"exchanges"`
		Products      []string `json:"products"`
		OrderTypes    []string `json:"order_types"`
		AvatarURL     string   `json:"avatar_url"`
		UserID        string   `json:"user_id"`
		ApiKey        string   `json:"api_key"`
		AccessToken   string   `json:"access_token"`
		PublicToken   string   `json:"public_token"`
		EncToken      string   `json:"enctoken"`
		RefreshToken  string   `json:"refresh_token"`
		Silo          string   `json:"silo"`
		LoginTime     string   `json:"login_time"`
		Meta          *struct {
			DematConsent string `json:"demat_consent"`
		} `json:"meta"`
	} `json:"data,omitempty"`
	Error *struct {
		ErrorType string `json:"error_type"`
	} `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

// kiteLogin logs into the Zerodha API and returns the request ID for further authentication.
func kiteLogin(client *http.Client, userID, password string) (int, string) {
	form := url.Values{}
	form.Set("user_id", userID)
	form.Set("password", password)
	form.Set("type", "user_id")

	req, err := http.NewRequest("POST", BASE_URL_LOGIN, bytes.NewBufferString(form.Encode()))
	if err != nil {
		log.Printf("Login request creation error: %v", err)
		return ERROR, ""
	}

	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://kite.zerodha.com/")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Login request error: %v", err)
		return ERROR, ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading login response: %v", err)
		return ERROR, ""
	}
	log.Println("Login Response:", string(body))

	var result LoginResponse
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("Error unmarshalling login response: %v", err)
		return ERROR, err.Error()
	}

	if result.Status != "success" {
		log.Printf("Login failed with status: %v", result.Status)
		return ERROR, result.Status
	}

	return SUCCESS, result.Data.RequestID
}

// generateTOTP generates a Time-based One-Time Password using the provided secret.
func generateTOTP(secret string) (int, string) {
	totpCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		log.Printf("Error generating TOTP: %v", err)
		return ERROR, err.Error()
	}
	return SUCCESS, totpCode
}

// performTwoFA performs two-factor authentication using TOTP and returns the session cookies.
func performTwoFA(client *http.Client, userID, requestID, twofaValue string) (int, string, []*http.Cookie) {
	form := url.Values{}
	form.Set("user_id", userID)
	form.Set("request_id", requestID)
	form.Set("twofa_value", twofaValue)
	form.Set("twofa_type", "totp")

	req, err := http.NewRequest("POST", "https://kite.zerodha.com/api/twofa", bytes.NewBufferString(form.Encode()))
	if err != nil {
		log.Printf("2FA request error: %v", err)
		return ERROR, "", nil
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://kite.zerodha.com")
	req.Header.Set("Referer", "https://kite.zerodha.com/")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("2FA response error: %v", err)
		return ERROR, "", nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading 2FA response: %v", err)
		return ERROR, "", nil
	}
	log.Println("2FA Response:", string(body))

	u, _ := url.Parse("https://kite.zerodha.com")
	cookies := client.Jar.Cookies(u)

	for _, c := range cookies {
		if c.Name == "kf_session" {
			log.Println("✅ kf_session =", c.Value)
			return SUCCESS, c.Value, cookies
		}
	}

	log.Println("2FA failed to retrieve session cookie")
	return ERROR, "", nil
}

// getRequestTokenWithSession gets the request token from the redirect URL using session cookies.
func getRequestTokenWithSession(apiKey string, cookies []*http.Cookie) (int, string) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Stop at redirect
		},
	}

	req, err := http.NewRequest("GET", "https://kite.zerodha.com/connect/login?v=3&api_key="+apiKey, nil)
	if err != nil {
		log.Printf("Redirect request error: %v", err)
		return ERROR, ""
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Redirect response error: %v", err)
		return ERROR, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		loc := resp.Header.Get("Location")
		log.Println("🎯 Final redirect URL (should contain request_token):", loc)
		return SUCCESS, loc
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading unexpected response: %v", err)
		return ERROR, "redirect failed"
	}
	log.Println("Unexpected response body:", string(body))
	return ERROR, "redirect failed"
}

// followConnectFinishURL follows the final redirect URL to retrieve the request token.
func followConnectFinishURL(finishURL string, cookies []*http.Cookie) (int, string) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Stop at redirect
		},
	}

	req, err := http.NewRequest("GET", finishURL, nil)
	if err != nil {
		log.Printf("Connect finish request creation failed: %v", err)
		return ERROR, ""
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Connect finish request failed: %v", err)
		return ERROR, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		final := resp.Header.Get("Location")
		log.Println("🚀 FINAL Redirect URL (contains request_token):", final)
		return SUCCESS, final
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading connect finish response: %v", err)
		return ERROR, "No redirect"
	}
	log.Println("Unexpected connect finish response:", string(body))
	return ERROR, "No redirect"
}

// extractRequestToken parses the URL and returns the request_token parameter.
func extractRequestToken(redirectURL string) (string, error) {
	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %v", err)
	}

	queryParams := parsedURL.Query()
	requestToken := queryParams.Get("request_token")

	if requestToken == "" {
		return "", fmt.Errorf("request_token not found in URL")
	}

	return requestToken, nil
}

// SHA256Hash generates the SHA-256 hash of a given string.
func SHA256Hash(input string) string {
	hash := sha256.New()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}

// getAccessToken generates an access token for Zerodha broker using the request token.
func getAccessToken(apiKey, appSecret, requestToken string) (string, string, error) {
	url := "https://api.kite.trade/session/token"

	checksum := SHA256Hash(apiKey + requestToken + appSecret)
	payloadInString := fmt.Sprintf("api_key=%s&request_token=%s&checksum=%s", apiKey, requestToken, checksum)

	req, err := http.NewRequest("POST", url, strings.NewReader(payloadInString))
	if err != nil {
		return "", "", errors.New("error while creating request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Kite-Version", "3")

	client := http.DefaultClient

	resp, err := client.Do(req)
	if err != nil {
		return "", "", errors.New("error while sending request")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", errors.New("error while reading response body")
	}

	log.Println("Access Token Response:", string(body))

	var authVerifyResp zerodhaAuthVerifyResponse
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&authVerifyResp); err != nil {
		return "", "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", errors.New("non-200 status code")
	}

	if authVerifyResp.Status != "success" {
		return "", "", errors.New("invalid response status")
	}

	return authVerifyResp.Data.UserName, authVerifyResp.Data.AccessToken, nil
}

// writeDataToFile writes the access token data to a file named after the user ID.
func writeDataToFile(name, token string) error {
	// Get the current date in the format "YYYY-MM-DD"
	today := time.Now().Format("2006-01-02")

	// Create a map with the required data
	acstokenframe := map[string]string{
		"Date":   today,
		"apiKey": APP_ID,
		"name":   name,
		"token":  token,
		"userID": UserID,
	}

	// Create a file with the user ID as the name
	fileName := UserID + ".json"
	file, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer file.Close()

	// Marshal the data into JSON format
	jsonData, err := json.MarshalIndent(acstokenframe, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	// Write the data to the file
	file.Write(jsonData)
	fmt.Printf("Data written to file %s\n", fileName)
	return nil
}

func main() {
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatalf("Error creating cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	// Step 1 - Login
	loginStatus, requestID := kiteLogin(client, UserID, PassWord)
	if loginStatus == ERROR {
		log.Fatal("Login failed")
	}
	log.Println("✅ Kite Login successful")

	// Step 2 - TOTP
	totpStatus, totpCode := generateTOTP(TOTP_KEY)
	if totpStatus == ERROR {
		log.Fatal("TOTP generation failed")
	}
	log.Println("✅ TOTP generated")

	// Step 3 - 2FA
	twoFABStatus, _, cookies := performTwoFA(client, UserID, requestID, totpCode)
	if twoFABStatus == ERROR {
		log.Fatal("2FA failed")
	}
	log.Println("✅ 2FA successful")

	// Step 4 - Get request_token from redirect URL
	requestTokenStatus, intermediateRedirect := getRequestTokenWithSession(APP_ID, cookies)
	if requestTokenStatus == ERROR {
		log.Fatal("Failed to get request_token from redirect")
	}
	log.Println("✅ Request token retrieved")

	// Step 5 - Hit /connect/finish and get final redirect with request_token
	finishStatus, finalRedirect := followConnectFinishURL(intermediateRedirect, cookies)
	if finishStatus == ERROR {
		log.Fatal("Failed to get final redirect")
	}
	log.Println("✅ Final redirect retrieved")

	requestToken, err := extractRequestToken(finalRedirect)
	if err != nil {
		log.Fatalf("Error extracting request token: %v", err)
	}
	log.Println("✅ Request token extracted")

	name, accessToken, err := getAccessToken(APP_ID, APP_SECRET, requestToken)
	if err != nil {
		log.Fatalf("Error getting access token: %v", err)
	}
	log.Println("✅ Access token retrieved")

	err = writeDataToFile(name, accessToken)
	if err != nil {
		log.Fatalf("Error saving access token: %v", err)
	}
}
