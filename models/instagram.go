package models

import (
	"encoding/json"
	"errors"
	"strconv"
	"github.com/Cloose28/go-instagram/constants"
	"github.com/Cloose28/go-instagram/utils"
	"github.com/parnurzeal/gorequest"
)

type Instagram struct {
	Username     string
	Password     string
	loggedInUser
	AgentPool    *utils.SuperAgentPool
	Inbox        *Inbox
	TimelineFeed *TimelineFeed
}

type DefaultResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type FollowingResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	NextMaxId int64 `json:"next_max_id"`
	Users     json.RawMessage `json:"users"`
}

type FollowersResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	NextMaxId string `json:"next_max_id"`
	Users     json.RawMessage `json:"users"`
}

type HashtagFeedResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	NextMaxId string `json:"next_max_id"`
	Items     json.RawMessage `json:"items"`
}

type AboutUserResponse struct {
	User    loggedInUser `json:"user"`
	Status  string `json:"status"`
	Message string `json:"message"`
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
	LoggedInUser loggedInUser `json:"logged_in_user"`
	DefaultResponse
}

type loggedInUser struct {
	Pk int64 `json:"pk"`
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

type FollowParams struct {
	ID        string
	RankToken string
	MaxID     string
}

type likeResponse struct {
	DefaultResponse
}

func (ig *Instagram) Login() error {
	for i := 0; i < ig.AgentPool.Len(); i++ {
		igSigKeyVersion, signedBody := ig.CreateSignature()

		payload := loginRequest{
			IgSigKeyVersion: igSigKeyVersion,
			SignedBody:      signedBody,
		}

		jsonData, _ := json.Marshal(payload)

		agent := ig.AgentPool.Get()
		defer ig.AgentPool.Put(agent)

		_, body, _ := ig.SendRequest(agent.Post(constants.ROUTES.Login).
				Type("multipart").
				Send(string(jsonData)))

		var resp loginResponse
		json.Unmarshal([]byte(body), &resp)

		if resp.Status == "fail" {
			return errors.New(resp.Message)
		}

		// store user info
		ig.Pk = resp.LoggedInUser.Pk
	}

	return nil
}

func (ig *Instagram) GetHashtagFeed(tag string, maxId string) ([]constants.MediaItem, string, error) {
	params := HashtagFeedParams{
		ID: tag,
	}
	if maxId != "" {
		params.MaxID = maxId
	}

	url := constants.GetURL("TagFeed", params)

	agent := ig.AgentPool.Get()

	defer ig.AgentPool.Put(agent)

	_, body, err := ig.SendRequest(agent.Get(url).
			Type("form"))
	if err != nil {
		return nil, "", errors.New("error request")
	}

	var resp HashtagFeedResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return nil, "", errors.New(resp.Message)
	}

	var items []constants.MediaItem
	if resp.Status == "ok" {
		json.Unmarshal(resp.Items, &items)
	} else {
		return nil, "Repeat", nil
	}

	return items, resp.NextMaxId, nil
}

func (ig *Instagram) GetUserFollowing(userId string, maxId string) ([]constants.UserCompetitor, string, error) {
	params := FollowParams{
		ID: userId,
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

	var resp FollowingResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return nil, "", errors.New(resp.Message)
	}

	var users []constants.UserCompetitor
	if resp.Status == "ok" {
		json.Unmarshal(resp.Users, &users)
	} else {
		return nil, "Repeat", nil
	}

	return users, strconv.FormatInt(resp.NextMaxId, 10), nil
}

func (ig *Instagram) GetUserFollowers(userId string, maxId string) ([]constants.UserCompetitor, string, error) {
	params := FollowParams{
		ID: userId,
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

	var resp FollowersResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return nil, "", errors.New(resp.Message)
	}

	var users []constants.UserCompetitor
	if resp.Status == "ok" {
		json.Unmarshal(resp.Users, &users)
	} else {
		return nil, "Repeat", nil
	}

	return users, resp.NextMaxId, nil
}

func (ig *Instagram) GetUserIdByName(userName string) (string, error) {
	url := constants.GetURL("Users", struct{ ID string }{ID: userName})

	igSigKeyVersion, signedBody := ig.CreateSignature()

	payload := loginRequest{
		IgSigKeyVersion: igSigKeyVersion,
		SignedBody: signedBody,
	}

	jsonData, _ := json.Marshal(payload)

	agent := ig.AgentPool.Get()

	defer ig.AgentPool.Put(agent)

	_, body, err := ig.SendRequest(agent.Get(url).
			Type("multipart").
			Send(string(jsonData)))
	if err != nil {
		return "", errors.New("error request")
	}

	var resp AboutUserResponse
	json.Unmarshal([]byte(body), &resp)

	if resp.Status == "fail" {
		return "", errors.New(resp.Message)
	}

	return strconv.FormatInt(resp.User.Pk, 10), nil
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
	return agent.
	Set("Connection", "close").
			Set("Accept", "*/*").
			Set("X-IG-Connection-Type", "WIFI").
			Set("X-IG-Capabilities", "3QI=").
			Set("Accept-Language", "en-US").
			Set("Host", constants.HOSTNAME).
			Set("User-Agent", "Instagram " + constants.APP_VERSION + " Android (21/5.1.1; 401dpi; 1080x1920; Oppo; A31u; A31u; en_US)").
			End()
}
