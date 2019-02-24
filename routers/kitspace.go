package routers

import (
	"bytes"
	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/context"
	"encoding/json"
	"fmt"
	"github.com/go-macaron/csrf"
	"github.com/go-macaron/session"
	"io/ioutil"
	"net/http"
	"strings"

	"gitea.com/macaron/csrf"
	"gitea.com/macaron/session"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/setting"
)

type Message struct {
	User  *models.User
	Csrf  string
	Route string
}

func Kitspace(ctx *context.Context, sess session.Store, x csrf.CSRF) []byte {
	m := Message{User: ctx.User, Csrf: x.GetToken(), Route: strings.Replace(ctx.Link, "/kitspace", "", 1)}
	fmt.Printf("%+v\n", ctx)
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	url := "http://localhost:3001/"
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(b))
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
