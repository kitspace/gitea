// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2017 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package models

import (
	// Needed for jpeg support
	"errors"
	"regexp"
)

var (
	ErrInvalidStripePriceID = errors.New("Invalid Stripe Price ID given.")
)

var pricePattern = regexp.MustCompile(`$price_.*`)

type PurchaseStatus int

const (
	PurchaseOrdered PurchaseStatus = iota
	PurchaseCancelled
)

type Purchase struct {
	ID              int64 `xorm:"pk autoincr"`
	Buyer           *User `xorm:"-"`
	StripePriceID   string
	Status          PurchaseStatus `xorm:"NOT NULL DEFAULT 0"`
	Quantity        int            `xorm:"NOT NULL DEFAULT 1"`
	DeliveryAddress string
}

type CreatePurchaseOptions struct {
	Buyer           *User
	StripePriceID   string
	Quantity        int
	DeliveryAddress string
}

// IsUsableRepoName returns true when repository is usable
func IsStripePriceID(name string) error {
	if !pricePattern.MatchString(name) {
		return ErrInvalidStripePriceID
	}
	return nil
}

// CreateRepository creates a repository for the user/organization.
func CreatePurchase(ctx DBContext, options CreatePurchaseOptions) (err error) {
	return nil
}
