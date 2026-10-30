/*
 * Copyright (C) 2025, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package adblock_set

import (
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
)

type AdblockMatcher struct {
	blacklist *domain.MixMatcher[struct{}]
	whitelist *domain.MixMatcher[struct{}]
}

func (m *AdblockMatcher) Match(s string) (struct{}, bool) {
	// 1. Check whitelist. If matched, it's NOT a hit for the adblock set.
	if _, ok := m.whitelist.Match(s); ok {
		return struct{}{}, false
	}

	// 2. Check blacklist.
	if _, ok := m.blacklist.Match(s); ok {
		return struct{}{}, true
	}

	return struct{}{}, false
}
