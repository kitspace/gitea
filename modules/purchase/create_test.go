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
	// get an admin user
	user, err := models.GetUserByID(1)
	assert.NoError(t, err, "GetUserByID")
	options := models.CreatePurchaseOptions{
		Buyer:           user,
		StripePriceID:   "price_test",
		Quantity:        1,
		DeliveryAddress: "123 Fake Street",
	}
	assert.NotNil(t, user)
	assert.NotNil(t, options)
	purchase, err := CreatePurchase(options)
	assert.NoError(t, err, "CreatePurchase")
	assert.NotNil(t, purchase)
}
