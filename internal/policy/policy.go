package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
)

type Policy struct {
	Version   string     `json:"Version"`
	ID        string     `json:"Id"`
	Statement Statements `json:"Statement"`
}

type Statements []Statement

type Statement struct {
	SID          string         `json:"Sid"`
	Effect       string         `json:"Effect"`
	Principal    PrincipalValue `json:"Principal"`
	NotPrincipal PrincipalValue `json:"NotPrincipal"`
	Action       StringList     `json:"Action"`
	NotAction    StringList     `json:"NotAction"`
	Resource     StringList     `json:"Resource"`
	NotResource  StringList     `json:"NotResource"`
	Condition    Conditions     `json:"Condition"`
}

type StringList []string

type PrincipalValue struct {
	Any    bool
	Values map[string][]string
}

type Conditions map[string]map[string][]string

func Parse(data []byte) (Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy JSON: %w", err)
	}
	if len(p.Statement) == 0 {
		return Policy{}, errors.New("policy does not contain any statements")
	}
	return p, nil
}

func ReadFile(path string) ([]byte, error) {
	// #nosec G304 -- this CLI intentionally reads the exact path the user supplied.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	return data, nil
}

func (s *Statements) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	switch data[0] {
	case '{':
		var stmt Statement
		if err := json.Unmarshal(data, &stmt); err != nil {
			return err
		}
		*s = Statements{stmt}
		return nil
	case '[':
		var stmts []Statement
		if err := json.Unmarshal(data, &stmts); err != nil {
			return err
		}
		*s = Statements(stmts)
		return nil
	default:
		return fmt.Errorf("unexpected Statement payload: %s", string(data))
	}
}

func (s *StringList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	switch data[0] {
	case '"':
		var single string
		if err := json.Unmarshal(data, &single); err != nil {
			return err
		}
		*s = StringList{single}
		return nil
	case '[':
		var values []string
		if err := json.Unmarshal(data, &values); err != nil {
			return err
		}
		*s = StringList(values)
		return nil
	default:
		return fmt.Errorf("unexpected string list payload: %s", string(data))
	}
}

func (p *PrincipalValue) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if bytes.Equal(data, []byte(`"*"`)) {
		p.Any = true
		p.Values = nil
		return nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("unexpected principal payload: %w", err)
	}

	p.Values = make(map[string][]string, len(obj))
	for k, raw := range obj {
		var list StringList
		if err := json.Unmarshal(raw, &list); err != nil {
			return err
		}
		p.Values[k] = []string(list)
	}
	return nil
}

func (c *Conditions) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}

	var raw map[string]map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	parsed := make(Conditions, len(raw))
	for operator, entries := range raw {
		parsed[operator] = make(map[string][]string, len(entries))
		for key, value := range entries {
			list, err := parseConditionValueList(value)
			if err != nil {
				return err
			}
			parsed[operator][key] = list
		}
	}
	*c = parsed
	return nil
}

func parseConditionValueList(data []byte) ([]string, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil, nil
	}
	switch data[0] {
	case '"':
		var single string
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, err
		}
		return []string{single}, nil
	case 't', 'f':
		var value bool
		if err := json.Unmarshal(data, &value); err != nil {
			return nil, err
		}
		return []string{strconv.FormatBool(value)}, nil
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		var value json.Number
		if err := json.Unmarshal(data, &value); err != nil {
			return nil, err
		}
		return []string{value.String()}, nil
	case '[':
		var rawItems []json.RawMessage
		if err := json.Unmarshal(data, &rawItems); err != nil {
			return nil, err
		}
		values := make([]string, 0, len(rawItems))
		for _, item := range rawItems {
			parsed, err := parseConditionValueList(item)
			if err != nil {
				return nil, err
			}
			values = append(values, parsed...)
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unexpected condition value payload: %s", string(data))
	}
}

func sortedKeys[K ~string, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	return keys
}
