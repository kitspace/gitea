// Copyright 2019 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package purchase

import (
	"path/filepath"
	"testing"

	"code.gitea.io/gitea/models"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	models.MainTest(m, filepath.Join("..", ".."))
}

func TestCreatePurchase(t *testing.T) {
	assert.NoError(t, models.PrepareTestDatabase())
}
