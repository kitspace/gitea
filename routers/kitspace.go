package routers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path"
	"strings"

	"gitea.com/macaron/csrf"
	"gitea.com/macaron/session"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/setting"
)

type KitspaceSession struct {
	User *models.User
	Csrf string
}

func Kitspace(ctx *context.Context, sess session.Store, x csrf.CSRF) (int, []byte) {
	url := ctx.Req.URL
	url.Scheme = "http"
	url.Host = "frontend:3000"
	url.Path = strings.Replace(
		ctx.Link,
		path.Join(setting.AppSubURL, "/kitspace"),
		"",
		1,
	)

	m := KitspaceSession{
		User: ctx.User,
		Csrf: x.GetToken(),
	}

	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("GET", url.String(), bytes.NewBuffer(b))
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	ctx.Resp.Header().Set("Content-Type", resp.Header.Get("Content-Type"))

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	return resp.StatusCode, body
}
