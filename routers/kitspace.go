package routers

import (
	"bytes"
	"code.gitea.io/gitea/modules/context"
	"io/ioutil"
	"net/http"
)

func Kitspace(ctx *context.Context) []byte {
	url := "http://localhost:3001/"
	data := []byte(`{"hello": "world"}`)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return body
}
