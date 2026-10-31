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
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
)

// ParseRules reads AdBlock rules from r and adds them to blacklist and whitelist matchers.
func ParseRules(r io.Reader, blacklist, whitelist *domain.MixMatcher[struct{}]) error {
	scanner := bufio.NewScanner(r)
	valid, invalid := 0, 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '!' || line[0] == '#' {
			continue
		}

		// Handle hosts file format: "0.0.0.0 domain1 domain2" or "127.0.0.1 domain"
		if fields := strings.Fields(line); len(fields) >= 2 {
			if ip := net.ParseIP(fields[0]); ip != nil {
				for _, host := range fields[1:] {
					if strings.HasPrefix(host, "#") {
						break
					}
					if host != "" && host != "localhost" {
						if err := blacklist.Add("full:"+host, struct{}{}); err != nil {
							invalid++
						} else {
							valid++
						}
					}
				}
				continue
			}
		}

		// Handle whitelists
		isWhitelist := false
		if strings.HasPrefix(line, "@@") {
			isWhitelist = true
			line = line[2:]
		}

		// Handle comments in rules (e.g., rule # comment)
		// But in AdBlock, # is usually for element hiding (##) or CSS selectors.
		// For DNS rules, we ignore anything starting with #.
		if strings.Contains(line, "##") || strings.Contains(line, "#?#") || strings.Contains(line, "#$#") {
			continue
		}

		// A dollar sign is a regexp anchor in native regexp: and /.../
		// patterns. Only ABP-style rules may have $options.
		if !strings.HasPrefix(line, "regexp:") && !strings.HasPrefix(line, "/") {
			if idx := strings.IndexByte(line, '$'); idx != -1 {
				line = line[:idx]
			}
		}

		if line == "" {
			continue
		}

		target := blacklist
		if isWhitelist {
			target = whitelist
		}

		if err := parseAndAddRule(line, target); err != nil {
			invalid++
			continue
		}
		valid++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if invalid > 0 && valid == 0 {
		return fmt.Errorf("all %d adblock rules were invalid", invalid)
	}
	return nil
}

func parseAndAddRule(rule string, m *domain.MixMatcher[struct{}]) error {
	rule = strings.TrimSuffix(rule, "^")
	if rule == "" {
		return fmt.Errorf("empty adblock rule")
	}

	// 0. Native MosDNS rules: type:pattern
	if strings.Contains(rule, ":") {
		typ, pattern, _ := strings.Cut(rule, ":")
		switch typ {
		case "full", "domain", "regexp", "keyword":
			if pattern == "" {
				return fmt.Errorf("empty %s rule", typ)
			}
			return m.Add(rule, struct{}{})
		}
	}

	// 1. Regex: /regexp/
	if strings.HasPrefix(rule, "/") && strings.HasSuffix(rule, "/") && len(rule) > 2 {
		return m.Add("regexp:"+rule[1:len(rule)-1], struct{}{})
	}

	// 2. Subdomain: ||example.com^
	if strings.HasPrefix(rule, "||") {
		domainStr := rule[2:]
		if strings.HasSuffix(domainStr, "^") {
			domainStr = domainStr[:len(domainStr)-1]
		}
		if domainStr == "" {
			return fmt.Errorf("empty domain rule")
		}
		return m.Add("domain:"+domainStr, struct{}{})
	}

	// 3. Exact match: |example.com|
	if strings.HasPrefix(rule, "|") && strings.HasSuffix(rule, "|") && len(rule) > 2 {
		return m.Add("full:"+rule[1:len(rule)-1], struct{}{})
	}

	// 4. Keyword: *keyword*
	if strings.HasPrefix(rule, "*") && strings.HasSuffix(rule, "*") && len(rule) > 2 {
		return m.Add("keyword:"+rule[1:len(rule)-1], struct{}{})
	}

	// 5. Default:
	if strings.HasPrefix(rule, "^") {
		return m.Add("full:"+strings.TrimPrefix(rule, "^"), struct{}{})
	}
	return m.Add("domain:"+rule, struct{}{})
}
