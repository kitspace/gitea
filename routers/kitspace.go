package routers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"

	"github.com/go-macaron/csrf"
	"github.com/go-macaron/session"

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
	m := Message{
		User: ctx.User,
		Csrf: x.GetToken(),
		Route: strings.Replace(
			ctx.Link,
			path.Join(setting.AppSubURL, "/kitspace"), "", 1,
		),
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
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
