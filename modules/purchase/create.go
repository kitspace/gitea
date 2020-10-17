// Copyright 2019 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package purchase

import (
	"code.gitea.io/gitea/models"
)

// CreatePurchase creates a purchase for a user
func CreatePurchase() (*models.Purchase, error) {
	if err := models.WithTx(func(ctx models.DBContext) error {
		return nil
	}); err != nil {
		return nil, err
	}
	return nil, nil
}
