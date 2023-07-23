package tool

import (
	"encoding/json"
	"strings"
)

func Jsonify(data map[string]string) string {
	jsonStr, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return strings.ReplaceAll(string(jsonStr), `"`, `\"`)
}
