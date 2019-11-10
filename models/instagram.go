package models

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Cloose28/go-instagram/constants"
	"github.com/Cloose28/go-instagram/utils"
	"github.com/hieven/go-instagram/src/protos"
	"github.com/parnurzeal/gorequest"
	"log"
	"net/http"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	uuid "github.com/satori/go.uuid"
)

type Instagram struct {
	Username     string
	Password     string
	Proxy        string
	Pk           int64
	AgentPool    *utils.SuperAgentPool
	Inbox        *Inbox
	TimelineFeed *TimelineFeed
	Cookies []*http.Cookie
}

type DefaultResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type PostsResponse struct {
	DefaultResponse
	NextMaxId string          `json:"next_max_id"`
	Items     json.RawMessage `json:"items"`
}

type UsersResponse struct {
	DefaultResponse
	NextMaxId string          `json:"next_max_id"`
	Users     json.RawMessage `json:"users"`
}

type CommentsResponse struct {
	DefaultResponse
	NextMaxId string          `json:"next_max_id"`
	Comments  json.RawMessage `json:"comments"`
}

type ItemsResponse struct {
	DefaultResponse
	NextMaxId string          `json:"next_max_id"`
	Items     json.RawMessage `json:"items"`
}

type SectionResponse struct {
	DefaultResponse
	NextMaxId string    `json:"next_max_id"`
	Sections  []constants.Section `json:"sections"`
}


type LocationSectionResponse struct {
	DefaultResponse
	NextMaxId string    `json:"next_max_id"`
	Sections []*constants.LocationSection `json:"sections"`
}

type AboutUserResponse struct {
	DefaultResponse
	User LoggedInUser `json:"user"`
}

type loginRequest struct {
	SignedBody      string `json:"signed_body"`
	IgSigKeyVersion string `json:"ig_sig_key_version"`
}

type loginRequestWithMaxId struct {
	SignedBody      string `json:"signed_body"`
	IgSigKeyVersion string `json:"ig_sig_key_version"`
	NextMaxId       string `json:"max_id"`
}

type loginResponse struct {
	LoggedInUser LoggedInUser `json:"logged_in_user"`
	DefaultResponse
}

type LoggedInUser struct {
	Pk            int64 `json:"pk"`
	FollowerCount int   `json:"follower_count"`
}

type likeRequest struct {
	MediaID string `json:"media_id"`
	Src     string `json:"src"`
	loginRequest
}

type HashtagFeedParams struct {
	ID    string
	MaxID string
}

type DefaultParams struct {
	ID        string
	RankToken string
	MaxID     string
}

type likeResponse struct {
	DefaultResponse
}

func (ig *Instagram) Login() (cookies []string, err error) {
	for i := 0; i < ig.AgentPool.Len(); i++ {
		igSigKeyVersion, signedBody := ig.CreateSignature()

		payload := loginRequest{
			IgSigKeyVersion: igSigKeyVersion,
			SignedBody:      signedBody,
		}

		jsonData, _ := json.Marshal(payload)

		agent := ig.AgentPool.Get()
		defer ig.AgentPool.Put(agent)

		resp, body, _ := ig.SendRequest(agent.Post(constants.ROUTES.Login).
			Type("multipart").
			Send(string(jsonData)))

		var loginResponse loginResponse
		json.Unmarshal([]byte(body), &loginResponse)
		if loginResponse.Status == "fail" {
			return cookies, errors.New(loginResponse.Message)
		}

		// store user info
		ig.Pk = loginResponse.LoggedInUser.Pk
		log.Println(resp.Header["Set-Cookie"])
		//ig.Cookies = setCookies(resp.Header["Set-Cookie"])
		cookies = resp.Header["Set-Cookie"]
	}

	return 
}

//func setCookies(cookies []string) []http.Cookie {
//	var cookie []http.Cookie
//}

func (ig *Instagram) GetFeedOf(feedName, tag, maxId string) (json.RawMessage, string, error) {
	params := HashtagFeedParams{
		ID: tag,
	}
	if maxId != "" {
		params.MaxID = maxId
	}

	url := constants.GetURL(feedName, params)

	agent := ig.AgentPool.Get()

	defer ig.AgentPool.Put(agent)

	_, body, err := ig.SendRequest(agent.Get(url).
		Type("form"))
	if err != nil {
		return nil, "", err[0]
	}

	var resp ItemsResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		if !strings.Contains(resp.Message, "wait a few minutes") {
			return nil, "", errors.New(resp.Message)
		}
	} else if resp.Status == "ok" {
		return resp.Items, resp.NextMaxId, nil
	}

	return nil, "Repeat", nil
}

func (ig *Instagram) GetUserFollowing(userId string, maxId string) ([]constants.UserCompetitor, string, error) {
	params := DefaultParams{
		ID:        userId,
		RankToken: utils.GenerateRankToken(userId),
	}
	if maxId != "" {
		params.MaxID = maxId
	}

	url := constants.GetURL("Followings", params)

	agent := ig.AgentPool.Get()

	defer ig.AgentPool.Put(agent)

	_, body, err := ig.SendRequest(agent.Get(url).
		Type("form"))
	if err != nil {
		return nil, "", errors.New("error request")
	}

	var resp UsersResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return nil, "", errors.New(resp.Message)
	}

	var users []constants.UserCompetitor
	if resp.Status == "ok" {
		json.Unmarshal(resp.Users, &users)
	} else {
		return nil, "Repeat", errors.New(fmt.Sprintf("%v", resp))
	}

	return users, resp.NextMaxId, nil
}

func (ig *Instagram) GetUserFollowers(userId string, maxId string) ([]constants.UserCompetitor, string, error) {
	params := DefaultParams{
		ID:        userId,
		RankToken: utils.GenerateRankToken(userId),
	}
	if maxId != "" {
		params.MaxID = maxId
	}

	url := constants.GetURL("Followers", params)

	agent := ig.AgentPool.Get()

	defer ig.AgentPool.Put(agent)

	_, body, err := ig.SendRequest(agent.Get(url).
		Type("form"))
	if err != nil {
		return nil, "", errors.New("error request")
	}

	var resp UsersResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return nil, "", errors.New(resp.Message)
	}

	var users []constants.UserCompetitor
	if resp.Status == "ok" {
		json.Unmarshal(resp.Users, &users)
	} else {
		return nil, "Repeat", errors.New(fmt.Sprintf("%v", resp))
	}

	return users, resp.NextMaxId, nil
}

type LocationSectionRequest struct {
	Tab  string `json:"tab"`
	UUID string `json:"_uuid"`
}

type LocationSectionTab string

const (
	LocationSectionTabRanked LocationSectionTab = "ranked"
	LocationSectionTabRecent LocationSectionTab = "recent"
)

func (ig *Instagram) GetLocationSections(id, maxId, sectionTab string) ([]*constants.LocationSection, string, error) {
	params := DefaultParams{
		ID: id,
	}
	if maxId != "" {
		params.MaxID = maxId
	}

	url := constants.GetURL("LocationSections", params)

	agent := ig.AgentPool.Get()
	defer ig.AgentPool.Put(agent)

	internalReq := &protos.LocationSectionRequest{
		UUID: utils.GenerateUUID(),
		Tab:  sectionTab,
	}

	_, body, err := ig.SendRequest(agent.Post(url).
		Type("multipart").
		SendStruct(internalReq))
	if err != nil {
		return nil, "", err[0]
	}

	var resp LocationSectionResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return nil, "", errors.New(resp.Message)
	}

	if resp.Status != "ok" {
		return nil, "", errors.New(fmt.Sprintf("%v", resp))
	}

	return resp.Sections, resp.NextMaxId, nil
}

func (ig *Instagram) GetLocationIdByName(location, maxId string) ([]constants.Location, string, error) {
	params := struct {
		DefaultParams
		Query string
	}{
		Query: location,
	}
	if maxId != "" {
		params.MaxID = maxId
	}

	url := constants.GetURL("LocationSearch", params)

	agent := ig.AgentPool.Get()
	defer ig.AgentPool.Put(agent)

	_, body, err := ig.SendRequest(agent.Get(url).
		Type("form"))
	if err != nil {
		return nil, "", err[0]
	}

	var resp ItemsResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return nil, "", errors.New(resp.Message)
	}

	var items []constants.Location
	if resp.Status == "ok" {
		json.Unmarshal(resp.Items, &items)
	} else {
		return nil, "", errors.New(fmt.Sprintf("%v", resp))
	}

	return items, resp.NextMaxId, nil
}

const (
	SigCsrfToken = "missing"
	SigDeviceID  = "android-b256317fd493b848"
	SigKey       = "109513c04303341a7daf27bb41b268e633b30dcc65a3fe14503f743176113869"
	SigVersion   = "4"
	AppVersion   = "27.0.0.7.97"

	Scheme   = "https"
	Hostname = "i.instagram.com"

	InstagramStatusFail = "fail"
)

func (ig *Instagram) GetUserByNameV2(userName string) (LoggedInUser, error) {
	url := constants.GetURL("Users", struct{ ID string }{ID: userName})

	sigPayload := &SignaturePayload{
		Csrftoken:         SigCsrfToken,
		DeviceID:          SigDeviceID,
		UUID:              generateUUID(),
		UserName:          ig.Username,
		Password:          ig.Password,
		LoginAttemptCount: 0,
	}
	igSigKeyVersion, signedBody, err := generateSignature(sigPayload)
	if err != nil {
		return LoggedInUser{}, err
	}
	payload := loginRequest{
		IgSigKeyVersion: igSigKeyVersion,
		SignedBody:      signedBody,
	}
	req := gorequest.New().
		Post(url).
		Type("multipart").
		SendStruct(payload)
	req.
		Set("Connection", "close").
		Set("Accept", "*/*").
		Set("X-IG-Connection-Type", "WIFI").
		Set("X-IG-Capabilities", "3QI=").
		Set("Accept-Language", "en-US").
		Set("Host", Hostname).
		Set("User-Agent", "Instagram "+AppVersion+" Android (21/5.1.1; 401dpi; 1080x1920; Oppo; A31u; A31u; en_US)").
		AddCookies(ig.Cookies)
	resp, body, errs := req.End()

	if len(errs) > 0 {
		err = errs[0]
	}
	log.Println(resp)
	log.Println(body)
	return LoggedInUser{}, nil
}
type SignaturePayload struct {
	Csrftoken         string `json:"_csrftoken"`
	DeviceID          string `json:"device_id"`
	UUID              string `json:"_uuid"`
	UserName          string `json:"username"`
	Password          string `json:"password"`
	LoginAttemptCount int    `json:"login_attempt_count"`
}

func generateUUID() string {
	return uuid.Must(uuid.NewV4()).String()
}

func generateSignature(payload *SignaturePayload) (string, string, error) {
	payloadBytes, _ := json.Marshal(payload)

	h := hmac.New(sha256.New, []byte(SigKey))
	h.Write(payloadBytes)

	var b []byte
	hash := hex.EncodeToString(h.Sum(b))

	sigVersion := SigVersion
	signedBody := hash + "." + string(payloadBytes)

	return sigVersion, signedBody, nil
}

func (ig *Instagram) GetUserByName(userName string) (LoggedInUser, error) {
	url := constants.GetURL("Users", struct{ ID string }{ID: userName})

	igSigKeyVersion, signedBody := ig.CreateSignature()

	payload := loginRequest{
		IgSigKeyVersion: igSigKeyVersion,
		SignedBody:      signedBody,
	}

	jsonData, _ := json.Marshal(payload)

	agent := ig.AgentPool.Get()

	defer ig.AgentPool.Put(agent)
	var resp AboutUserResponse

	_, body, err := ig.SendRequest(agent.Get(url).
		Type("multipart").
		Send(string(jsonData)))
	if err != nil {
		return resp.User, err[0]
	}

	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return resp.User, errors.New(resp.Message)
	}

	return resp.User, nil
}

func (ig *Instagram) GetPosts(userId, maxId string) ([]constants.MediaItem, string, error) {
	params := DefaultParams{
		ID:        userId,
		RankToken: utils.GenerateRankToken(userId),
	}
	if maxId != "" {
		params.MaxID = maxId
	}
	url := constants.GetURL("UserFeed", params)

	agent := ig.AgentPool.Get()
	defer ig.AgentPool.Put(agent)

	_, body, err := ig.SendRequest(agent.Get(url).
		Type("form"))
	if err != nil {
		return nil, "", errors.New("error request")
	}

	var resp PostsResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return nil, "", errors.New(resp.Message)
	}

	var items []constants.MediaItem
	if resp.Status == "ok" {
		json.Unmarshal(resp.Items, &items)
	} else {
		return nil, "Repeat", errors.New(fmt.Sprintf("%v", resp))
	}

	return items, resp.NextMaxId, nil
}

func (ig *Instagram) GetLikers(mediaId, maxId string) ([]constants.UserCompetitor, string, error) {
	params := DefaultParams{
		ID:        mediaId,
		RankToken: utils.GenerateRankToken(mediaId),
	}
	if maxId != "" {
		params.MaxID = maxId
	}
	url := constants.GetURL("Likers", params)

	agent := ig.AgentPool.Get()
	defer ig.AgentPool.Put(agent)

	_, body, err := ig.SendRequest(agent.Get(url).
		Type("form"))
	if err != nil {
		return nil, "", errors.New("error request")
	}

	var resp UsersResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return nil, "", errors.New(resp.Message)
	}

	var users []constants.UserCompetitor
	if resp.Status == "ok" {
		json.Unmarshal(resp.Users, &users)
	} else {
		return nil, "Repeat", errors.New(fmt.Sprintf("%v", resp))
	}

	return users, resp.NextMaxId, nil
}

func (ig *Instagram) GetComments(mediaId, maxId string) ([]constants.UserCompetitor, string, error) {
	params := DefaultParams{
		ID:        mediaId,
		RankToken: utils.GenerateRankToken(mediaId),
	}
	if maxId != "" {
		params.MaxID = maxId
	}
	url := constants.GetURL("Comments", params)

	agent := ig.AgentPool.Get()
	defer ig.AgentPool.Put(agent)

	_, body, err := ig.SendRequest(agent.Get(url).
		Type("form"))
	if err != nil {
		return nil, "", errors.New("error request")
	}

	var resp CommentsResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return nil, "", errors.New(resp.Message)
	}

	var users [] struct {
		User constants.UserCompetitor `json:"user"`
	}
	if resp.Status == "ok" {
		json.Unmarshal(resp.Comments, &users)
	} else {
		return nil, "Repeat", errors.New(fmt.Sprintf("%v", resp))
	}
	result := make([]constants.UserCompetitor, 0)
	for _, user := range users {
		result = append(result, user.User)
	}
	return result, resp.NextMaxId, nil
}

func (ig *Instagram) Like(mediaID string) error {
	url := constants.GetURL("Like", struct{ ID string }{ID: mediaID})

	igSigKeyVersion, signedBody := ig.CreateSignature()

	payload := likeRequest{
		MediaID: mediaID,
		Src:     "profile",
	}
	payload.IgSigKeyVersion = igSigKeyVersion
	payload.SignedBody = signedBody

	jsonData, _ := json.Marshal(payload)

	agent := ig.AgentPool.Get()
	defer ig.AgentPool.Put(agent)

	_, body, _ := ig.SendRequest(agent.Post(url).
		Type("multipart").
		Send(string(jsonData)))

	var resp loginResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return errors.New(resp.Message)
	}

	return nil
}

func (ig *Instagram) Unlike(mediaID string) error {
	url := constants.GetURL("Unlike", struct{ ID string }{ID: mediaID})

	igSigKeyVersion, signedBody := ig.CreateSignature()

	payload := likeRequest{
		MediaID: mediaID,
		Src:     "profile",
	}
	payload.IgSigKeyVersion = igSigKeyVersion
	payload.SignedBody = signedBody

	jsonData, _ := json.Marshal(payload)

	agent := ig.AgentPool.Get()
	defer ig.AgentPool.Put(agent)

	_, body, _ := ig.SendRequest(agent.Post(url).
		Type("multipart").
		Send(string(jsonData)))

	var resp loginResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return errors.New(resp.Message)
	}

	return nil
}

func (ig *Instagram) CreateSignature() (sigVersion string, signedBody string) {
	data := struct {
		Csrftoken         string `json:"_csrftoken"`
		DeviceID          string `json:"device_id"`
		UUID              string `json:"_uuid"`
		UserName          string `json:"username"`
		Password          string `json:"password"`
		LoginAttemptCount int    `json:"login_attempt_count"`
	}{
		Csrftoken:         "missing",
		DeviceID:          "android-b256317fd493b848",
		UUID:              utils.GenerateUUID(),
		UserName:          ig.Username,
		Password:          ig.Password,
		LoginAttemptCount: 0,
	}

	jsonData, _ := json.Marshal(data)

	return utils.GenerateSignature(jsonData)
}

func (ig *Instagram) SendRequest(agent *gorequest.SuperAgent) (gorequest.Response, string, []error) {
	if ig.Proxy != "" {
		agent.Proxy(ig.Proxy)
	}
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
	}
	agent.Client = &http.Client{Transport: transCfg}
	agent.Proxy("http://127.0.0.1:8080")
	return agent.
		Timeout(time.Minute).
		Set("Connection", "close").
		Set("Accept", "*/*").
		Set("X-IG-Connection-Type", "WIFI").
		Set("X-IG-Capabilities", "3QI=").
		Set("Accept-Language", "en-US").
		Set("Host", constants.HOSTNAME).
		Set("User-Agent", "Instagram "+constants.APP_VERSION+" Android (21/5.1.1; 401dpi; 1080x1920; Oppo; A31u; A31u; en_US)").
		End()
}
