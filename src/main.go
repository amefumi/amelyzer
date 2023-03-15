// Copyright 2013 The Walk Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"Amelyzer/src/ui"
)

func main() {
	err := ui.MakeUI()
	if err != nil {
		return
	}
}
