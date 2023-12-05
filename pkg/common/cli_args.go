// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import "os"

// helper function to get an environment variable or a default value
func GetEnv(name string, defaultValue string) string {
	value, ok := os.LookupEnv(name)
	if !ok {
		return defaultValue
	}
	return value
}
