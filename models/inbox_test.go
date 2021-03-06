package models_test

import (
	"testing"

	. "github.com/Cloose28/go-instagram/InstagramModels"
	"github.com/Cloose28/go-instagram/constants"
	"github.com/Cloose28/go-instagram/testUtils"
	"github.com/jarcoal/httpmock"
	"github.com/parnurzeal/gorequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type InboxTestSuite struct {
	suite.Suite

	ig    *Instagram
	inbox Inbox
}

func TestInboxSuite(t *testing.T) {
	suite.Run(t, new(InboxTestSuite))
}

func (suite *InboxTestSuite) SetupSuite() {
	gorequest.DisableTransportSwap = true

	suite.ig = &Instagram{
		Username: "even",
		Password: "qweasd",
	}
}

func (suite *InboxTestSuite) TearDownSuite() {
	httpmock.DeactivateAndReset()
}

func (suite *InboxTestSuite) SetupTest() {
	pool, _ := testUtils.MockAgentPool(1)

	suite.ig.AgentPool = pool
	suite.inbox.Instagram = suite.ig
}

func (suite *InboxTestSuite) TearDownTest() {
	httpmock.Reset()
}

func (suite *InboxTestSuite) TestGetFeedSuccess() {
	assert := assert.New(suite.T())
	inbox := suite.inbox

	responder := testUtils.NewMockResponder(200, "inboxFeed")
	httpmock.RegisterResponder("GET", constants.ROUTES.Inbox, responder)

	threads, err := inbox.GetFeed()

	assert.Len(threads[0].Items, 1)
	assert.Nil(err)
}

func (suite *InboxTestSuite) TestGetFeedLoginRequired() {
	assert := assert.New(suite.T())
	inbox := suite.inbox

	responder := testUtils.NewMockResponder(400, "loginRequired")
	httpmock.RegisterResponder("GET", constants.ROUTES.Inbox, responder)

	threads, err := inbox.GetFeed()

	assert.Len(threads, 0)
	assert.EqualError(err, "login_required")
}

func (suite *InboxTestSuite) TestApproveAllThreadsSuccess() {
	assert := assert.New(suite.T())
	inbox := suite.inbox

	responder := testUtils.NewMockResponder(200, "inboxApproveAllThreadsSuccess")
	httpmock.RegisterResponder("POST", constants.ROUTES.ThreadsApproveAll, responder)

	err := inbox.ApproveAllThreads()

	assert.Nil(err)
}

func (suite *InboxTestSuite) TestApproveAllThreadsLoginRequired() {
	assert := assert.New(suite.T())
	inbox := suite.inbox

	responder := testUtils.NewMockResponder(400, "loginRequired")
	httpmock.RegisterResponder("POST", constants.ROUTES.ThreadsApproveAll, responder)

	err := inbox.ApproveAllThreads()

	assert.EqualError(err, "login_required")
}
