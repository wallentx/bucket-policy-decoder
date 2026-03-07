package policy

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type RenderOptions struct {
	Color bool
}

type renderer struct {
	color bool
}

func Render(p Policy) string {
	return RenderWithOptions(p, RenderOptions{})
}

func RenderPlainEnglish(p Policy) string {
	return RenderPlainEnglishWithOptions(p, RenderOptions{})
}

func RenderStatementPlainEnglish(stmt Statement) string {
	return RenderStatementPlainEnglishWithOptions(stmt, RenderOptions{})
}

func RenderStatementPlainEnglishWithOptions(stmt Statement, opts RenderOptions) string {
	r := renderer{color: opts.Color}
	return r.sentenceForStatement(stmt)
}

func RenderWithOptions(p Policy, opts RenderOptions) string {
	r := renderer{color: opts.Color}
	return r.render(p)
}

func RenderPlainEnglishWithOptions(p Policy, opts RenderOptions) string {
	r := renderer{color: opts.Color}
	return r.renderPlainEnglish(p)
}

func ShouldColorizeTerminalOutput(f *os.File) bool {
	if f == nil {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func (r renderer) render(p Policy) string {
	var b strings.Builder

	fmt.Fprintf(&b, "This policy has %d statement", len(p.Statement))
	if len(p.Statement) != 1 {
		b.WriteString("s")
	}
	b.WriteString(".\n")

	allows, denies := countEffects(p.Statement)
	if denies > 0 {
		fmt.Fprintf(&b, "- %d explicit deny statement", denies)
		if denies != 1 {
			b.WriteString("s")
		}
		b.WriteString(".\n")
	}
	if allows > 0 {
		fmt.Fprintf(&b, "- %d allow statement", allows)
		if allows != 1 {
			b.WriteString("s")
		}
		b.WriteString(".\n")
	}
	if denies > 0 && allows > 0 {
		b.WriteString("- Explicit denies override matching allows.\n")
	}

	b.WriteString("\nPlain-English reading:\n")
	b.WriteString(r.renderPlainEnglish(p))

	b.WriteString("\nStatement breakdown:\n")
	for idx, stmt := range p.Statement {
		r.renderStatement(&b, idx, stmt)
	}

	return b.String()
}

func (r renderer) renderPlainEnglish(p Policy) string {
	var b strings.Builder
	for idx, stmt := range p.Statement {
		fmt.Fprintf(&b, "%d. %s\n", idx+1, RenderStatementPlainEnglishWithOptions(stmt, RenderOptions{Color: r.color}))
	}
	return b.String()
}

func (r renderer) renderStatement(b *strings.Builder, idx int, stmt Statement) {
	fmt.Fprintf(b, "[%d]", idx+1)
	if stmt.SID != "" {
		fmt.Fprintf(b, " %s", stmt.SID)
	}
	b.WriteByte('\n')
	fmt.Fprintf(b, "  Effect: %s\n", strings.ToUpper(fallback(stmt.Effect, "UNKNOWN")))
	fmt.Fprintf(b, "  Principals: %s\n", r.describePrincipal(stmt))
	fmt.Fprintf(b, "  Actions: %s\n", r.describeActionBlock(stmt))
	fmt.Fprintf(b, "  Resources: %s\n", r.describeResourceBlock(stmt))
	conditions := r.describeConditions(stmt.Condition)
	if len(conditions) == 0 {
		b.WriteString("  Conditions: none\n")
	} else {
		b.WriteString("  Conditions:\n")
		for _, condition := range conditions {
			fmt.Fprintf(b, "    - %s\n", condition)
		}
	}
}

func (r renderer) sentenceForStatement(stmt Statement) string {
	subject := r.describePrincipal(stmt)
	actions := r.describeActionBlock(stmt)
	resources := r.describeResourceBlock(stmt)
	activity, hasActivity := r.describeActivity(stmt)
	sentence := fmt.Sprintf("It applies %s to %s on %s", actions, subject, resources)
	conditionPrefix := "when "

	switch strings.ToLower(stmt.Effect) {
	case "allow":
		if hasActivity {
			sentence = fmt.Sprintf("It allows %s to %s", subject, activity)
		} else {
			sentence = fmt.Sprintf("It allows %s to use %s on %s", subject, actions, resources)
		}
		conditionPrefix = "only when "
	case "deny":
		if hasActivity {
			sentence = fmt.Sprintf("It prevents %s from being able to %s", subject, activity)
		} else {
			sentence = fmt.Sprintf("It prevents %s from using %s on %s", subject, actions, resources)
		}
	}
	if len(stmt.Condition) > 0 {
		sentence += " " + conditionPrefix + strings.Join(r.describeConditions(stmt.Condition), "; ")
	}
	return sentence + "."
}

func countEffects(stmts []Statement) (allows, denies int) {
	for _, stmt := range stmts {
		switch strings.ToLower(stmt.Effect) {
		case "allow":
			allows++
		case "deny":
			denies++
		}
	}
	return allows, denies
}

func (r renderer) describePrincipal(stmt Statement) string {
	switch {
	case stmt.NotPrincipal.Any:
		return r.paintPrincipalText("everyone") + " except the listed principals"
	case len(stmt.NotPrincipal.Values) > 0:
		return r.paintPrincipalText("everyone") + " except " + r.describePrincipalValue(stmt.NotPrincipal)
	case stmt.Principal.Any:
		return r.paintPrincipalText("everyone")
	case len(stmt.Principal.Values) > 0:
		return r.describePrincipalValue(stmt.Principal)
	default:
		return "the specified principals"
	}
}

func (r renderer) describePrincipalValue(value PrincipalValue) string {
	if value.Any {
		return r.paintPrincipalText("everyone")
	}

	var groups []string
	for _, principalType := range sortedKeys(value.Values) {
		var entries []string
		for _, raw := range value.Values[principalType] {
			entries = append(entries, r.describePrincipalEntry(principalType, raw))
		}
		groups = append(groups, joinHuman(entries))
	}
	return joinHuman(groups)
}

func (r renderer) describePrincipalEntry(principalType, raw string) string {
	switch principalType {
	case "AWS":
		return r.describeAWSPrincipal(raw)
	case "Service":
		return fmt.Sprintf("the AWS service %s", r.paintService(raw))
	case "CanonicalUser":
		return fmt.Sprintf("the canonical user %s", raw)
	case "Federated":
		return fmt.Sprintf("the federated identity %s", raw)
	default:
		return fmt.Sprintf("%s principal %s", principalType, raw)
	}
}

func (r renderer) describeAWSPrincipal(raw string) string {
	if raw == "*" {
		return r.paintPrincipalText("everyone")
	}
	if len(raw) == 12 && digitsOnly(raw) {
		return fmt.Sprintf("AWS account %s", r.paintAccount(raw))
	}
	if strings.HasPrefix(raw, "arn:aws:iam::") {
		account, remainder, ok := strings.Cut(strings.TrimPrefix(raw, "arn:aws:iam::"), ":")
		if ok {
			switch {
			case remainder == "root":
				return fmt.Sprintf("AWS account %s", r.paintAccount(account))
			case account == "cloudfront" && strings.HasPrefix(remainder, "user/CloudFront Origin Access Identity "):
				return fmt.Sprintf(
					"CloudFront origin access identity %s",
					r.paintUser(strings.TrimPrefix(remainder, "user/CloudFront Origin Access Identity ")),
				)
			case strings.HasPrefix(remainder, "user/"):
				return fmt.Sprintf(
					"IAM user %s in account %s",
					r.paintUser(strings.TrimPrefix(remainder, "user/")),
					r.paintAccount(account),
				)
			case strings.HasPrefix(remainder, "role/"):
				return fmt.Sprintf(
					"IAM role %s in account %s",
					r.paintRole(strings.TrimPrefix(remainder, "role/")),
					r.paintAccount(account),
				)
			}
		}
	}
	return raw
}

func (r renderer) describeActionBlock(stmt Statement) string {
	switch {
	case len(stmt.NotAction) > 0:
		return "all actions except " + r.describeActions(stmt.NotAction)
	case len(stmt.Action) > 0:
		return r.describeActions(stmt.Action)
	default:
		return "the listed actions"
	}
}

func (r renderer) describeActions(actions []string) string {
	if len(actions) == 0 {
		return "the listed actions"
	}
	if hasOnly(actions, "*") {
		return r.paintAction("all actions")
	}
	if hasOnly(actions, "s3:*") {
		return r.paintAction("all S3 actions")
	}
	list := make([]string, 0, len(actions))
	for _, action := range actions {
		list = append(list, r.describeActionName(action))
	}
	return joinHuman(list)
}

func (r renderer) describeResourceBlock(stmt Statement) string {
	switch {
	case len(stmt.NotResource) > 0:
		return "every resource except " + r.describeResources(stmt.NotResource)
	case len(stmt.Resource) > 0:
		return r.describeResources(stmt.Resource)
	default:
		return "the listed resources"
	}
}

func (r renderer) describeResources(resources []string) string {
	if len(resources) == 0 {
		return "the listed resources"
	}

	buckets := r.groupBucketResources(resources)
	if buckets != "" {
		return buckets
	}

	list := make([]string, 0, len(resources))
	for _, resource := range resources {
		list = append(list, r.describeSingleResource(resource))
	}
	sort.Strings(list)
	return joinHuman(list)
}

func (r renderer) groupBucketResources(resources []string) string {
	set := make(map[string]bool, len(resources))
	for _, resource := range resources {
		set[resource] = true
	}

	var grouped []string
	used := make(map[string]bool)
	for _, resource := range resources {
		if used[resource] {
			continue
		}
		if bucket, ok := strings.CutPrefix(resource, "arn:aws:s3:::"); ok && !strings.Contains(bucket, "/") {
			prefix := resource + "/*"
			if set[prefix] {
				grouped = append(grouped, fmt.Sprintf("bucket %s and every object in it", r.paintBucket(bucket)))
				used[resource] = true
				used[prefix] = true
				continue
			}
		}
	}

	for _, resource := range resources {
		if !used[resource] {
			grouped = append(grouped, r.describeSingleResource(resource))
		}
	}
	if len(grouped) == 0 {
		return ""
	}
	sort.Strings(grouped)
	return joinHuman(grouped)
}

func (r renderer) describeSingleResource(resource string) string {
	if bucket, ok := strings.CutPrefix(resource, "arn:aws:s3:::"); ok {
		if bucket == "*" {
			return "every S3 bucket and object"
		}
		if strings.HasSuffix(bucket, "/*") {
			target := strings.TrimSuffix(bucket, "/*")
			if strings.Contains(target, "/") {
				name, path, _ := strings.Cut(target, "/")
				return fmt.Sprintf("objects in bucket %s path %s/*", r.paintBucket(name), r.paintPath(path))
			}
			return fmt.Sprintf("objects in bucket %s", r.paintBucket(target))
		}
		if strings.Contains(bucket, "/") {
			name, key, _ := strings.Cut(bucket, "/")
			return fmt.Sprintf("bucket %s path %s", r.paintBucket(name), r.paintPath(key))
		}
		return fmt.Sprintf("bucket %s", r.paintBucket(bucket))
	}
	return resource
}

func (r renderer) describeConditions(conditions Conditions) []string {
	if len(conditions) == 0 {
		return nil
	}

	var lines []string
	for _, operator := range sortedKeys(conditions) {
		entries := conditions[operator]
		for _, key := range sortedKeys(entries) {
			values := entries[key]
			lines = append(lines, r.describeCondition(operator, key, values))
		}
	}
	return lines
}

func (r renderer) describeCondition(operator, key string, values []string) string {
	if phrase, ok := r.describeConditionPhrase(operator, key, values); ok {
		return phrase
	}

	modifier, baseOperator, ifExists := splitConditionOperator(operator)
	valueText := r.joinQuotedValues(values)
	key = r.paintConditionKey(key)
	switch baseOperator {
	case "Bool":
		if len(values) == 1 {
			return fmt.Sprintf("%s is %s", key, values[0])
		}
	case "StringEquals", "ArnEquals", "NumericEquals", "DateEquals":
		return fmt.Sprintf("%s%s equals %s%s", qualifierPrefix(modifier), key, valueText, ifExistsSuffix(ifExists))
	case "StringNotEquals", "ArnNotEquals", "NumericNotEquals", "DateNotEquals":
		return fmt.Sprintf("%s%s does not equal %s%s", qualifierPrefix(modifier), key, valueText, ifExistsSuffix(ifExists))
	case "StringLike", "ArnLike":
		return fmt.Sprintf("%s%s matches %s%s", qualifierPrefix(modifier), key, valueText, ifExistsSuffix(ifExists))
	case "StringNotLike", "ArnNotLike":
		return fmt.Sprintf("%s%s does not match %s%s", qualifierPrefix(modifier), key, valueText, ifExistsSuffix(ifExists))
	case "NumericLessThan", "DateLessThan":
		return fmt.Sprintf("%s%s is less than %s%s", qualifierPrefix(modifier), key, valueText, ifExistsSuffix(ifExists))
	case "NumericLessThanEquals", "DateLessThanEquals":
		return fmt.Sprintf("%s%s is less than or equal to %s%s", qualifierPrefix(modifier), key, valueText, ifExistsSuffix(ifExists))
	case "NumericGreaterThan", "DateGreaterThan":
		return fmt.Sprintf("%s%s is greater than %s%s", qualifierPrefix(modifier), key, valueText, ifExistsSuffix(ifExists))
	case "NumericGreaterThanEquals", "DateGreaterThanEquals":
		return fmt.Sprintf("%s%s is greater than or equal to %s%s", qualifierPrefix(modifier), key, valueText, ifExistsSuffix(ifExists))
	case "Null":
		if len(values) == 1 && values[0] == "true" {
			return fmt.Sprintf("%s is absent", key)
		}
		if len(values) == 1 && values[0] == "false" {
			return fmt.Sprintf("%s is present", key)
		}
		return fmt.Sprintf("%s is null = %s", key, valueText)
	}
	return fmt.Sprintf("%s%s %s %s%s", qualifierPrefix(modifier), key, baseOperator, valueText, ifExistsSuffix(ifExists))
}

func (r renderer) describeConditionPhrase(operator, key string, values []string) (string, bool) {
	if len(values) == 0 {
		return "", false
	}

	modifier, baseOperator, ifExists := splitConditionOperator(operator)
	valueText := r.joinQuotedValues(values)
	switch {
	case baseOperator == "Bool" && key == "aws:SecureTransport" && len(values) == 1 && values[0] == "false":
		return "the request is not using HTTPS", true
	case baseOperator == "Bool" && key == "aws:SecureTransport" && len(values) == 1 && values[0] == "true":
		return "the request is using HTTPS", true
	case baseOperator == "Bool" && key == "aws:MultiFactorAuthPresent" && len(values) == 1 && values[0] == "true":
		return "MFA is present", true
	case baseOperator == "Bool" && key == "aws:MultiFactorAuthPresent" && len(values) == 1 && values[0] == "false":
		return "MFA is not present", true
	case baseOperator == "Null" && key == "aws:MultiFactorAuthAge" && len(values) == 1 && values[0] == "true":
		return "the request is not authenticated with MFA", true
	case baseOperator == "Null" && key == "aws:MultiFactorAuthAge" && len(values) == 1 && values[0] == "false":
		return "the request is authenticated with MFA", true
	case baseOperator == "NumericGreaterThan" && key == "aws:MultiFactorAuthAge":
		return "the MFA login is older than " + r.paintConditionValue(values[0]) + " seconds", true
	case baseOperator == "StringEquals" && key == "s3:x-amz-acl":
		return "the upload sets the ACL to " + valueText, true
	case baseOperator == "StringEquals" && key == "s3:x-amz-storage-class":
		return "the upload uses storage class " + valueText, true
	case baseOperator == "StringNotEquals" && key == "s3:x-amz-storage-class":
		return "the upload does not use storage class " + valueText, true
	case baseOperator == "StringEquals" && key == "s3:x-amz-server-side-encryption-aws-kms-key-id":
		return "the upload is encrypted with " + r.paintKMSKeyText("KMS key") + " " + valueText, true
	case baseOperator == "StringNotEquals" && key == "s3:x-amz-server-side-encryption-aws-kms-key-id":
		return "the upload is not encrypted with " + r.paintKMSKeyText("KMS key") + " " + valueText, true
	case baseOperator == "Null" && key == "s3:x-amz-server-side-encryption-aws-kms-key-id" && len(values) == 1 && values[0] == "true":
		return "the upload does not specify a " + r.paintKMSKeyText("KMS key"), true
	case baseOperator == "ArnNotEquals" && key == "s3:x-amz-server-side-encryption-aws-kms-key-id":
		if ifExists {
			return "the " + r.paintKMSKeyText("KMS key") + " header is present but it does not match " + valueText, true
		}
		return "the upload does not use " + r.paintKMSKeyText("KMS key") + " " + valueText, true
	case baseOperator == "StringEquals" && key == "aws:PrincipalOrgID":
		return "the caller belongs to AWS Organization " + valueText, true
	case (baseOperator == "StringEquals" || baseOperator == "ArnEquals") && key == "aws:SourceArn":
		return "the source ARN equals " + valueText, true
	case baseOperator == "IpAddress" && key == "aws:SourceIp":
		return "the request comes from IP range " + valueText, true
	case baseOperator == "NotIpAddress" && key == "aws:SourceIp":
		return "the request does not come from IP range " + valueText, true
	case baseOperator == "StringEquals" && key == "s3:RequestObjectTag/Project":
		return "the request sets object tag Project to " + valueText, true
	case baseOperator == "StringEquals" && key == "s3:RequestObjectTag/Department":
		return "the upload sets object tag Department to " + valueText, true
	case baseOperator == "StringEquals" && key == "s3:ExistingObjectTag/environment":
		return "the existing object tag environment equals " + valueText, true
	case baseOperator == "StringEquals" && key == "aws:SourceAccount":
		return "the source account is " + valueText, true
	case baseOperator == "ArnLike" && key == "aws:SourceArn":
		return "the source ARN matches " + valueText, true
	case baseOperator == "ArnEquals" && key == "aws:SourceArn":
		return "the source ARN equals " + valueText, true
	case baseOperator == "StringNotEquals" && key == "aws:PrincipalServiceNamesList":
		return "the caller service name is not " + valueText, true
	case baseOperator == "StringEquals" && key == "s3:delimiter":
		return "the listing uses delimiter " + valueText, true
	case baseOperator == "StringEquals" && key == "s3:prefix":
		return "the listing is limited to prefix " + valueText, true
	case baseOperator == "StringLike" && key == "s3:prefix":
		return "the listing is limited to prefixes matching " + valueText, true
	case baseOperator == "StringEquals" && key == "s3:RequestObjectTagKeys":
		if modifier == "ForAnyValue" {
			return "the requested object tag keys include at least one of " + valueText, true
		}
		return "the requested object tag keys equal " + valueText, true
	case baseOperator == "StringEquals" && key == "s3:InventoryAccessibleOptionalFields" && modifier == "ForAllValues":
		return "the requested inventory optional fields are limited to " + valueText, true
	case baseOperator == "StringEquals" && key == "s3:InventoryAccessibleOptionalFields" && modifier == "ForAnyValue":
		return "the requested inventory optional fields include at least one of " + valueText, true
	default:
		return "", false
	}
}

func splitConditionOperator(operator string) (modifier, base string, ifExists bool) {
	base = operator
	if strings.Contains(base, ":") {
		modifier, base, _ = strings.Cut(base, ":")
	}
	if strings.HasSuffix(base, "IfExists") {
		base = strings.TrimSuffix(base, "IfExists")
		ifExists = true
	}
	return modifier, base, ifExists
}

func qualifierPrefix(modifier string) string {
	switch modifier {
	case "ForAnyValue":
		return "any value of "
	case "ForAllValues":
		return "all values of "
	default:
		return ""
	}
}

func ifExistsSuffix(ifExists bool) string {
	if ifExists {
		return " if present"
	}
	return ""
}

func (r renderer) joinQuotedValues(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, r.paintConditionValue(strconv.Quote(value)))
	}
	return joinHuman(quoted)
}

func (r renderer) paintBucket(value string) string {
	return r.paint(value, "1;34")
}

func (r renderer) paintAccount(value string) string {
	return r.paint(value, "1;36")
}

func (r renderer) paintRole(value string) string {
	return r.paint(value, "1;35")
}

func (r renderer) paintUser(value string) string {
	return r.paint(value, "38;5;213")
}

func (r renderer) paintService(value string) string {
	return r.paint(value, "1;32")
}

func (r renderer) paintPrincipalText(value string) string {
	return r.paintWords(value, "1;92")
}

func (r renderer) paintAction(value string) string {
	return r.paintWords(value, "1;33")
}

func (r renderer) paintKMSKeyText(value string) string {
	return r.paintWords(value, "38;5;177")
}

func (r renderer) paintConditionKey(value string) string {
	return r.paint(value, "38;5;81")
}

func (r renderer) paintConditionValue(value string) string {
	return r.paint(value, "38;5;215")
}

func (r renderer) paintPath(value string) string {
	return r.paint(value, "38;5;110")
}

func (r renderer) paint(value, code string) string {
	if !r.color || value == "" {
		return value
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func (r renderer) paintWords(value, code string) string {
	if !r.color || value == "" {
		return value
	}

	parts := strings.Split(value, " ")
	for index, part := range parts {
		if part == "" {
			continue
		}
		parts[index] = r.paint(part, code)
	}
	return strings.Join(parts, " ")
}

func joinHuman(values []string) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	case 2:
		return values[0] + " and " + values[1]
	default:
		return strings.Join(values[:len(values)-1], ", ") + ", and " + values[len(values)-1]
	}
}

func hasOnly(values []string, want string) bool {
	return len(values) == 1 && values[0] == want
}

func digitsOnly(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func fallback(value, fallbackValue string) string {
	if value == "" {
		return fallbackValue
	}
	return value
}
