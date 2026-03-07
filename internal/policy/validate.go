package policy

import (
	"fmt"
	"regexp"
	"strings"
)

type Severity string

const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
)

var ErrValidationFailed = fmt.Errorf("policy failed offline validation")

type Finding struct {
	Severity Severity
	Path     string
	Message  string
}

type ValidationResult struct {
	Findings []Finding
	UsedAWS  bool
}

func Validate(p Policy) ValidationResult {
	var result ValidationResult

	if p.Version != "" && p.Version != "2008-10-17" && p.Version != "2012-10-17" {
		result.addError("Version", `must be "2008-10-17" or "2012-10-17"`)
	}
	if len(p.Statement) == 0 {
		result.addError("Statement", "must contain at least one statement")
		return result
	}

	for i, stmt := range p.Statement {
		validateStatement(&result, i, stmt)
	}

	return result
}

func (r ValidationResult) HasErrors() bool {
	for _, finding := range r.Findings {
		if finding.Severity == SeverityError {
			return true
		}
	}
	return false
}

func (r ValidationResult) HasWarnings() bool {
	for _, finding := range r.Findings {
		if finding.Severity == SeverityWarning {
			return true
		}
	}
	return false
}

func (r ValidationResult) Render(color bool) string {
	if len(r.Findings) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("Issues:\n")
	for _, finding := range r.Findings {
		label := string(finding.Severity)
		if color {
			switch finding.Severity {
			case SeverityError:
				label = "\x1b[1;31m" + label + "\x1b[0m"
			case SeverityWarning:
				label = "\x1b[1;33m" + label + "\x1b[0m"
			}
		}
		fmt.Fprintf(&b, "- %s %s: %s\n", label, finding.Path, finding.Message)
	}
	return b.String()
}

func (r *ValidationResult) Merge(other ValidationResult) {
	if other.UsedAWS {
		r.UsedAWS = true
	}
	r.Findings = append(r.Findings, other.Findings...)
}

func (r *ValidationResult) addError(path, message string) {
	r.Findings = append(r.Findings, Finding{
		Severity: SeverityError,
		Path:     path,
		Message:  message,
	})
}

func (r *ValidationResult) addWarning(path, message string) {
	r.Findings = append(r.Findings, Finding{
		Severity: SeverityWarning,
		Path:     path,
		Message:  message,
	})
}

var (
	actionPattern        = regexp.MustCompile(`^(\*|[a-z0-9-]+:[A-Za-z0-9*]+)$`)
	s3ResourcePattern    = regexp.MustCompile(`^arn:aws[a-z-]*:s3(?:::[^:]*)?:::[^ ]+$`)
	conditionBoolPattern = regexp.MustCompile(`^(true|false)$`)
)

func validateStatement(result *ValidationResult, index int, stmt Statement) {
	path := fmt.Sprintf("Statement[%d]", index)

	switch stmt.Effect {
	case "Allow", "Deny":
	default:
		result.addError(path+".Effect", `must be "Allow" or "Deny"`)
	}

	validatePrincipalBlock(result, path, stmt)
	validateActionBlock(result, path, stmt)
	validateResourceBlock(result, path, stmt)
	validateConditions(result, path, stmt.Condition)
}

func validatePrincipalBlock(result *ValidationResult, path string, stmt Statement) {
	hasPrincipal := stmt.Principal.Any || len(stmt.Principal.Values) > 0
	hasNotPrincipal := stmt.NotPrincipal.Any || len(stmt.NotPrincipal.Values) > 0

	switch {
	case hasPrincipal && hasNotPrincipal:
		result.addError(path, "must not set both Principal and NotPrincipal")
	case !hasPrincipal && !hasNotPrincipal:
		result.addError(path, "must set Principal or NotPrincipal")
	}

	if hasPrincipal {
		validatePrincipalValue(result, path+".Principal", stmt.Principal)
	}
	if hasNotPrincipal {
		validatePrincipalValue(result, path+".NotPrincipal", stmt.NotPrincipal)
	}
}

func validatePrincipalValue(result *ValidationResult, path string, value PrincipalValue) {
	if value.Any {
		return
	}

	for _, principalType := range sortedKeys(value.Values) {
		entries := value.Values[principalType]
		if len(entries) == 0 {
			result.addError(path+"."+string(principalType), "must not be empty")
			continue
		}
		for i, entry := range entries {
			entryPath := fmt.Sprintf("%s.%s[%d]", path, principalType, i)
			validatePrincipalEntry(result, entryPath, principalType, entry)
		}
	}
}

func validatePrincipalEntry(result *ValidationResult, path string, principalType, entry string) {
	if strings.TrimSpace(entry) == "" {
		result.addError(path, "must not be empty")
		return
	}

	switch principalType {
	case "AWS":
		switch {
		case entry == "*":
			return
		case digitsOnly(entry):
			if len(entry) != 12 {
				result.addError(path, "AWS account IDs must be 12 digits")
			}
		case strings.HasPrefix(entry, "arn:"):
			return
		default:
			result.addWarning(path, "AWS principal is usually a 12-digit account ID or an ARN")
		}
	case "Service":
		if !strings.Contains(entry, ".amazonaws.com") {
			result.addWarning(path, `service principal usually ends with ".amazonaws.com"`)
		}
	}
}

func validateActionBlock(result *ValidationResult, path string, stmt Statement) {
	hasAction := len(stmt.Action) > 0
	hasNotAction := len(stmt.NotAction) > 0

	switch {
	case hasAction && hasNotAction:
		result.addError(path, "must not set both Action and NotAction")
	case !hasAction && !hasNotAction:
		result.addError(path, "must set Action or NotAction")
	}

	for i, action := range stmt.Action {
		validateAction(result, fmt.Sprintf("%s.Action[%d]", path, i), action)
	}
	for i, action := range stmt.NotAction {
		validateAction(result, fmt.Sprintf("%s.NotAction[%d]", path, i), action)
	}
}

func validateAction(result *ValidationResult, path, action string) {
	if action == "" {
		result.addError(path, "must not be empty")
		return
	}
	if !actionPattern.MatchString(action) {
		result.addWarning(path, `action should usually look like "s3:GetObject" or "s3:*"`)
	}
}

func validateResourceBlock(result *ValidationResult, path string, stmt Statement) {
	hasResource := len(stmt.Resource) > 0
	hasNotResource := len(stmt.NotResource) > 0

	switch {
	case hasResource && hasNotResource:
		result.addError(path, "must not set both Resource and NotResource")
	case !hasResource && !hasNotResource:
		result.addError(path, "must set Resource or NotResource")
	}

	for i, resource := range stmt.Resource {
		validateResource(result, fmt.Sprintf("%s.Resource[%d]", path, i), resource)
	}
	for i, resource := range stmt.NotResource {
		validateResource(result, fmt.Sprintf("%s.NotResource[%d]", path, i), resource)
	}
}

func validateResource(result *ValidationResult, path, resource string) {
	if strings.TrimSpace(resource) == "" {
		result.addError(path, "must not be empty")
		return
	}
	if resource == "*" {
		return
	}
	if !strings.HasPrefix(resource, "arn:") {
		result.addWarning(path, `resource should usually be "*" or an ARN`)
		return
	}
	if strings.Contains(resource, ":s3") && !s3ResourcePattern.MatchString(resource) {
		result.addWarning(path, "S3 resource ARN format looks unusual")
	}
}

func validateConditions(result *ValidationResult, path string, conditions Conditions) {
	for _, operator := range sortedKeys(conditions) {
		entries := conditions[operator]
		if len(entries) == 0 {
			result.addWarning(path+".Condition."+operator, "operator has no keys")
			continue
		}
		for _, key := range sortedKeys(entries) {
			values := entries[key]
			entryPath := fmt.Sprintf("%s.Condition.%s.%s", path, operator, key)
			if len(values) == 0 {
				result.addError(entryPath, "must contain at least one value")
				continue
			}
			if key == "" {
				result.addError(entryPath, "condition key must not be empty")
			}
			_, baseOperator, _ := splitConditionOperator(operator)
			if baseOperator == "Bool" {
				for _, value := range values {
					if !conditionBoolPattern.MatchString(value) {
						result.addWarning(entryPath, `Bool conditions usually use "true" or "false"`)
					}
				}
			}
			if !knownConditionOperator(operator) {
				result.addWarning(path+".Condition."+operator, "operator is not in the built-in offline allowlist")
			}
		}
	}
}

func knownConditionOperator(operator string) bool {
	_, baseOperator, _ := splitConditionOperator(operator)
	switch baseOperator {
	case "ArnEquals",
		"ArnLike",
		"ArnNotEquals",
		"ArnNotLike",
		"BinaryEquals",
		"Bool",
		"DateEquals",
		"DateGreaterThan",
		"DateGreaterThanEquals",
		"DateLessThan",
		"DateLessThanEquals",
		"DateNotEquals",
		"IpAddress",
		"NotIpAddress",
		"Null",
		"NumericEquals",
		"NumericGreaterThan",
		"NumericGreaterThanEquals",
		"NumericLessThan",
		"NumericLessThanEquals",
		"NumericNotEquals",
		"StringEquals",
		"StringEqualsIgnoreCase",
		"StringLike",
		"StringNotEquals",
		"StringNotEqualsIgnoreCase",
		"StringNotLike":
		return true
	default:
		return false
	}
}
