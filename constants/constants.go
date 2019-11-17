package constants

import (
	"bytes"
	"html/template"
	"reflect"
)

const (
	SIG_KEY       = "2f6dcdf76deb0d3fd008886d032162a79b88052b5f50538c1ee93c4fe7d02e60"
	SIG_VERSION   = "4"
	APP_VERSION   = "10.8.0"
	TAG_FEED      = "TagFeed"
	LOCATION_FEED = "LocationFeed"

	SigCsrfToken = "missing"
	SigDeviceID  = "android-b256317fd493b848"
	SigKey       = "109513c04303341a7daf27bb41b268e633b30dcc65a3fe14503f743176113869"
	SigVersion   = "4"
	AppVersion   = "27.0.0.7.97"
)

type UserId struct {
	Pk int64 `json:"pk"`
}

type UserCompetitor struct {
	Username  string `json:"username"`
	Pk        int64  `json:"pk"`
	IsPrivate bool   `json:"is_private"`
	FullName  string `json:"full_name"`
}

type Location struct {
	LocationId struct {
		Pk int64 `json:"pk"`
	} `json:"location"`
}

type Content struct {
	Medias []MediaItem `json:"medias"`
}

type Section struct {
	LayoutContent Content `json:"layout_content"`
}

type MediaItem struct {
	Pk            int64          `json:"pk"`
	User          UserCompetitor `json:"user"`
	CommentsCount int64          `json:"comment_count"`
	LikesCount    int64          `json:"like_count"`
	MediaType     int64          `json:"media_type"`
}

type Media struct {
	Pk            int            `json:"pk"`
	User          UserCompetitor `json:"user"`
	CommentsCount int            `json:"comment_count"`
	LikesCount    int            `json:"like_count"`
	MediaType     int            `json:"media_type"`
}

type LocationSection struct {
	LayoutType    string                        `json:"layout_type"`
	LayoutContent *LocationSectionLayoutContent `json:"layout_content"`
}

type LocationSectionLayoutContent struct {
	Medias []*LocationSectionLayoutContentMedias `json:"medias"`
}

type LocationSectionLayoutContentMedias struct {
	Media *MediaItem `json:"media"`
}

type TagIntersect struct {
	User struct {
		Username string `json:"username"`
	} `json:"user"`
	Caption struct {
		Text string `json:"text"`
	} `json:"caption"`
}

var HOSTNAME = "i.instagram.com"
var WEB_HOSTNAME = "www.instagram.com"
var HOST = "https://" + HOSTNAME + "/"
var WEBHOST = "https://" + WEB_HOSTNAME + "/"
var API_ENDPOINT = HOST + "api/v1/"

func GetURL(name string, data interface{}) string {
	t := template.New("url template")

	r := reflect.ValueOf(ROUTES)
	f := reflect.Indirect(r).FieldByName(name).String()
	t, _ = t.Parse(f)

	var url bytes.Buffer
	t.Execute(&url, data)
	return url.String()
}

var ROUTES = struct {
	HOSTNAME     string
	WEB_HOSTNAME string
	HOST         string
	WEBHOST      string

	Comments             string
	ThreadsBroadcastText string
	Inbox                string
	Login                string
	LocationFeed         string
	LocationSearch       string
	LocationSections     string
	ThreadsApproveAll    string
	ThreadsShow          string
	TimelineFeed         string
	Like                 string
	Likers               string
	Unlike               string
	Users                string
	Followers            string
	Followings           string
	TagFeed              string
	UserFeed             string
}{
	HOSTNAME:     HOSTNAME,
	WEB_HOSTNAME: WEB_HOSTNAME,
	HOST:         HOST,
	WEBHOST:      WEBHOST,

	Comments:             API_ENDPOINT + "media/{{.ID}}/comments/?rank_token={{.RankToken}}{{if .MaxID}}&max_id={{.MaxID}}{{end}}",
	ThreadsBroadcastText: API_ENDPOINT + "direct_v2/threads/broadcast/text/",
	Inbox:                API_ENDPOINT + "direct_v2/inbox/",
	Login:                API_ENDPOINT + "accounts/login/",
	LocationFeed:         API_ENDPOINT + "feed/location/{{.ID}}/?{{if .MaxID}}&max_id={{.MaxID}}{{end}}",
	LocationSearch:       API_ENDPOINT + "fbsearch/places/?query={{.Query}}&rank_token={{.RankToken}}{{if .MaxID}}&max_id={{.MaxID}}{{end}}",
	LocationSections:     API_ENDPOINT + "locations/{{.ID}}/sections/?{{if .MaxID}}&max_id={{.MaxID}}{{end}}",
	ThreadsApproveAll:    API_ENDPOINT + "direct_v2/threads/approve_all/",
	ThreadsShow:          API_ENDPOINT + "direct_v2/threads/",
	TimelineFeed:         API_ENDPOINT + "feed/timeline/?rank_token={{.RankToken}}{{if .MaxID}}&max_id={{.MaxID}}{{end}}&ranked_content=true",
	Like:                 API_ENDPOINT + "media/{{.ID}}/like/",
	Likers:               API_ENDPOINT + "media/{{.ID}}/likers/?rank_token={{.RankToken}}{{if .MaxID}}&max_id={{.MaxID}}{{end}}",
	Unlike:               API_ENDPOINT + "media/{{.ID}}/unlike/",
	Users:                API_ENDPOINT + "users/{{.ID}}/usernameinfo/",
	TagFeed:              API_ENDPOINT + "feed/tag/{{.ID}}/?{{if .MaxID}}&max_id={{.MaxID}}{{end}}",
	UserFeed:             API_ENDPOINT + "feed/user/{{.ID}}/?rank_token={{.RankToken}}{{if .MaxID}}&max_id={{.MaxID}}{{end}}",
	Followers:            API_ENDPOINT + "friendships/{{.ID}}/followers/?rank_token={{.RankToken}}{{if .MaxID}}&max_id={{.MaxID}}{{end}}",
	Followings:           API_ENDPOINT + "friendships/{{.ID}}/following/?rank_token={{.RankToken}}{{if .MaxID}}&max_id={{.MaxID}}{{end}}",
}
