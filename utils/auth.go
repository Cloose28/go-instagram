package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/Cloose28/go-instagram/constants"
	uuid2 "github.com/satori/go.uuid"
)

func GenerateSignature(data []byte) (sigVersion string, signedBody string) {
	h := hmac.New(sha256.New, []byte(constants.SigKey))
	h.Write(data)

	var b []byte
	hash := hex.EncodeToString(h.Sum(b))

	sigVersion = constants.SigVersion
	signedBody = hash + "." + string(data)

	return sigVersion, signedBody
}

func GenerateUUID() (uuid string) {
	uuid = uuid2.Must(uuid2.NewV4()).String()

	return uuid
}

type RankTokenGenerator struct{}

func (generator RankTokenGenerator) GenerateRankToken(userID string) string {
	return userID + "_" + GenerateUUID()
}

func GenerateRankToken(userID string) string {
	return userID + "_" + GenerateUUID()
}
