// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
)

func main() {
	// variables declaration
	var resourceId string
	var clientId string

	// flags declaration using flag package
	flag.StringVar(&resourceId, "r", "", "Specify resource Id for which identity token is required")
	flag.StringVar(&clientId, "c", "", "Specify client Id for which identity token is required")
	flag.Parse() // after declaring flags we need to call it

	flag.Parse()
	if flag.NArg() != 0 || len(resourceId) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	identity := common.Identity{
		ClientId: clientId,
	}

	token, err := common.GetToken(resourceId, identity)
	if err != nil {
		fmt.Println("retrieving authentication token failed ", err)
	}

	fmt.Println("Token: ", token.AccessToken)
	fmt.Println("ExpiresIn: ", token.ExpiresIn)

	// token is a JWT token
	tokenFields := strings.Split(token.AccessToken, ".")

	fmt.Println(tokenFields[1])

	payload, _ := base64.URLEncoding.DecodeString(tokenFields[1] + " ")

	var payloadMap map[string]interface{}
	err = json.Unmarshal([]byte(payload), &payloadMap)

	if err != nil {
		fmt.Println("Failed to unmarshal identity bytes: ", err.Error())
	}

	audience := payloadMap["aud"].(string)
	identity.ClientId = payloadMap["appid"].(string)

	refreshToken, _ := common.GetToken(audience, identity)

	duration, _ := strconv.ParseInt(refreshToken.ExpiresIn, 10, 64)
	fmt.Println(time.Duration(1000 * 1000 * 1000 * duration))

}
