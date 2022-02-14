package auth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type tokenModel struct {
	Token     string    `json:"token"`
	Agent     string    `json:"agent"`
	ClientIP  string    `json:"client_ip"`
	UserId    int64     `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

type Authentication struct {
	URL       string
	Token     string
	HaveToken bool
	IsAuth    bool
	IsExpired bool
}

func NewAuth(request *http.Request, URL string) Authentication {
	auth := authentication()
	return auth(request, URL)
}

func authentication() func(request *http.Request, URL string) Authentication {
	return func(request *http.Request, URL string) Authentication {
		var authentication Authentication
		authentication.URL = URL
		authentication.SetTokenFromRequest(request)

		if authentication.HaveToken {
			authentication.checkToken()
		}

		return authentication
	}
}

// Check if token found or no
func (auth *Authentication) SetTokenFromRequest(request *http.Request) {
	authorization := request.Header["Authorization"]
	if len(authorization) == 0 {
		auth.HaveToken = false
		return
	}
	token := strings.Split(authorization[0], " ")
	if token == nil {
		auth.HaveToken = false
		return
	}
	auth.Token = token[1]
	auth.HaveToken = true
}

func (auth *Authentication) checkToken() {
	var model tokenModel
	postBody, _ := json.Marshal(map[string]string{
		"token": auth.Token,
	})

	// Make Request
	resp, err := http.Post(auth.URL, "application/json", bytes.NewBuffer(postBody))
	if err != nil {
		auth.IsAuth = false
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &model)

	if model.Token != "" {
		duration := model.ExpiredAt.Sub(time.Now()).Hours()
		if duration <= 0 {
			auth.IsExpired = true
			return
		}
		auth.IsAuth = true
	}
}
