package testUtils

import (
	"github.com/Cloose28/go-instagram/utils"
	"github.com/jarcoal/httpmock"
)

func MockAgentPool(capacity int) (*utils.SuperAgentPool, error) {
	pool, _ := utils.NewSuperAgentPool(capacity)

	for i := 0; i < pool.Len(); i++ {
		agent := pool.Get()
		httpmock.ActivateNonDefault(agent.Client)
		pool.Put(agent)
	}

	return pool, nil
}
