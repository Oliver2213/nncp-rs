// NNCP -- Node to Node copy, utilities for store-and-forward data exchange
// Copyright (C) 2016-2025 Sergey Matveev <stargrave@stargrave.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// NNCP -- Node to Node copy
package nncp

import (
	"encoding/base32"
	"runtime"
)

const (
	Warranty = `Copyright (C) 2016-2025 Sergey Matveev

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.`
	Base32Encoded32Len = 52
)

var (
	Version string = "8.11.0"

	Base32Codec *base32.Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

func VersionGet() string {
	return "NNCP version " + Version + " built with " + runtime.Version()
}
