package policy

import "fmt"

type resourceScopeKind int

const (
	resourceScopeUnknown resourceScopeKind = iota
	resourceScopeBucketOnly
	resourceScopeObjectOnly
	resourceScopeBucketAndObjects
)

type resourceScope struct {
	kind   resourceScopeKind
	bucket string
	path   string
}

var actionLabels = map[string]string{
	"s3:AbortMultipartUpload":       "cancel multipart uploads",
	"s3:DeleteObject":               "delete objects",
	"s3:DeleteObjectVersion":        "delete object versions",
	"s3:GetBucketAcl":               "read the bucket ACL",
	"s3:GetBucketLocation":          "read the bucket location",
	"s3:GetBucketPolicy":            "read the bucket policy",
	"s3:GetEncryptionConfiguration": "read default encryption settings",
	"s3:GetLifecycleConfiguration":  "read lifecycle rules",
	"s3:GetObject":                  "read/download objects",
	"s3:GetObjectAcl":               "read object ACLs",
	"s3:GetObjectVersion":           "read/download object versions",
	"s3:ListBucket":                 "list the bucket contents",
	"s3:ListBucketMultipartUploads": "list in-progress multipart uploads",
	"s3:PutBucketPolicy":            "change the bucket policy",
	"s3:PutEncryptionConfiguration": "change default encryption settings",
	"s3:PutInventoryConfiguration":  "change inventory settings",
	"s3:PutLifecycleConfiguration":  "change lifecycle rules",
	"s3:PutObject":                  "upload objects",
	"s3:PutObjectAcl":               "change object ACLs",
	"s3:PutObjectTagging":           "set object tags",
}

func (r renderer) describeActivity(stmt Statement) (string, bool) {
	if len(stmt.NotAction) > 0 || len(stmt.NotResource) > 0 || len(stmt.Action) == 0 {
		return "", false
	}

	scope, ok := classifyResourceScope(stmt.Resource)
	if !ok {
		return "", false
	}

	phrases := make([]string, 0, len(stmt.Action))
	for _, action := range stmt.Action {
		phrase, ok := r.actionActivity(action, scope)
		if !ok {
			return "", false
		}
		phrases = append(phrases, phrase)
	}

	return joinHuman(phrases), true
}

func classifyResourceScope(resources []string) (resourceScope, bool) {
	if len(resources) == 0 {
		return resourceScope{}, false
	}

	if len(resources) == 1 {
		scope, ok := parseS3Resource(resources[0])
		return scope, ok
	}

	if len(resources) == 2 {
		first, okFirst := parseS3Resource(resources[0])
		second, okSecond := parseS3Resource(resources[1])
		if !okFirst || !okSecond {
			return resourceScope{}, false
		}

		if first.bucket == second.bucket {
			switch {
			case first.kind == resourceScopeBucketOnly && second.kind == resourceScopeObjectOnly:
				return resourceScope{
					kind:   resourceScopeBucketAndObjects,
					bucket: first.bucket,
					path:   second.path,
				}, true
			case first.kind == resourceScopeObjectOnly && second.kind == resourceScopeBucketOnly:
				return resourceScope{
					kind:   resourceScopeBucketAndObjects,
					bucket: first.bucket,
					path:   first.path,
				}, true
			}
		}
	}

	return resourceScope{}, false
}

func parseS3Resource(resource string) (resourceScope, bool) {
	const prefix = "arn:aws:s3:::"

	if len(resource) == 0 || resource == "*" {
		return resourceScope{}, false
	}
	if len(resource) < len(prefix) || resource[:len(prefix)] != prefix {
		return resourceScope{}, false
	}

	target := resource[len(prefix):]
	for i := 0; i < len(target); i++ {
		if target[i] == '/' {
			bucket := target[:i]
			path := target[i+1:]
			if bucket == "" || path == "" {
				return resourceScope{}, false
			}
			return resourceScope{
				kind:   resourceScopeObjectOnly,
				bucket: bucket,
				path:   path,
			}, true
		}
	}

	return resourceScope{
		kind:   resourceScopeBucketOnly,
		bucket: target,
	}, true
}

func (r renderer) actionActivity(action string, scope resourceScope) (string, bool) {
	switch action {
	case "s3:*":
		switch {
		case scope.supportsBucket() && scope.supportsObjects():
			return r.paintActionMeaning("perform any S3 action") + " on " + r.bucketTarget(scope) + " and its objects", true
		case scope.supportsObjects():
			return r.paintActionMeaning("perform any S3 action") + " on " + r.objectTarget(scope), true
		case scope.supportsBucket():
			return r.paintActionMeaning("perform any S3 action") + " on " + r.bucketTarget(scope), true
		default:
			return "", false
		}
	case "s3:GetObject":
		if !scope.supportsObjects() {
			return "", false
		}
		return r.paintActionMeaning("read/download objects") + " from " + r.objectTarget(scope), true
	case "s3:GetObjectVersion":
		if !scope.supportsObjects() {
			return "", false
		}
		return r.paintActionMeaning("read/download object versions") + " from " + r.objectTarget(scope), true
	case "s3:PutObject":
		if !scope.supportsObjects() {
			return "", false
		}
		return r.paintActionMeaning("upload objects") + " to " + r.objectTarget(scope), true
	case "s3:DeleteObject":
		if !scope.supportsObjects() {
			return "", false
		}
		return r.paintActionMeaning("delete objects") + " from " + r.objectTarget(scope), true
	case "s3:DeleteObjectVersion":
		if !scope.supportsObjects() {
			return "", false
		}
		return r.paintActionMeaning("delete object versions") + " from " + r.objectTarget(scope), true
	case "s3:GetObjectAcl":
		if !scope.supportsObjects() {
			return "", false
		}
		return r.paintActionMeaning("read object ACLs") + " in " + r.objectTarget(scope), true
	case "s3:PutObjectAcl":
		if !scope.supportsObjects() {
			return "", false
		}
		return r.paintActionMeaning("change object ACLs") + " in " + r.objectTarget(scope), true
	case "s3:PutObjectTagging":
		if !scope.supportsObjects() {
			return "", false
		}
		return r.paintActionMeaning("set object tags") + " on " + r.objectTarget(scope), true
	case "s3:AbortMultipartUpload":
		if !scope.supportsObjects() {
			return "", false
		}
		return r.paintActionMeaning("cancel multipart uploads") + " in " + r.objectTarget(scope), true
	case "s3:ListBucket":
		if !scope.supportsBucket() {
			return "", false
		}
		return r.paintActionMeaning("list") + " " + r.bucketTarget(scope), true
	case "s3:ListBucketMultipartUploads":
		if !scope.supportsBucket() {
			return "", false
		}
		return r.paintActionMeaning("list in-progress multipart uploads") + " in " + r.bucketTarget(scope), true
	case "s3:GetBucketLocation":
		if !scope.supportsBucket() {
			return "", false
		}
		return r.paintActionMeaning("read the location of") + " " + r.bucketTarget(scope), true
	case "s3:GetBucketAcl":
		if !scope.supportsBucket() {
			return "", false
		}
		return r.paintActionMeaning("read the bucket ACL on") + " " + r.bucketTarget(scope), true
	case "s3:GetBucketPolicy":
		if !scope.supportsBucket() {
			return "", false
		}
		return r.paintActionMeaning("read the bucket policy on") + " " + r.bucketTarget(scope), true
	case "s3:PutBucketPolicy":
		if !scope.supportsBucket() {
			return "", false
		}
		return r.paintActionMeaning("change the bucket policy on") + " " + r.bucketTarget(scope), true
	case "s3:GetLifecycleConfiguration":
		if !scope.supportsBucket() {
			return "", false
		}
		return r.paintActionMeaning("read lifecycle rules on") + " " + r.bucketTarget(scope), true
	case "s3:PutLifecycleConfiguration":
		if !scope.supportsBucket() {
			return "", false
		}
		return r.paintActionMeaning("change lifecycle rules on") + " " + r.bucketTarget(scope), true
	case "s3:PutInventoryConfiguration":
		if !scope.supportsBucket() {
			return "", false
		}
		return r.paintActionMeaning("change inventory settings on") + " " + r.bucketTarget(scope), true
	case "s3:GetEncryptionConfiguration":
		if !scope.supportsBucket() {
			return "", false
		}
		return r.paintActionMeaning("read default encryption settings on") + " " + r.bucketTarget(scope), true
	case "s3:PutEncryptionConfiguration":
		if !scope.supportsBucket() {
			return "", false
		}
		return r.paintActionMeaning("change default encryption settings on") + " " + r.bucketTarget(scope), true
	default:
		return "", false
	}
}

func (r renderer) describeActionName(action string) string {
	switch action {
	case "*":
		return r.paintAction("all actions")
	case "s3:*":
		return r.paintAction("all S3 actions")
	default:
		label, ok := actionLabels[action]
		if !ok {
			return r.paintAction(action)
		}
		return fmt.Sprintf("%s (%s)", r.paintActionMeaning(label), r.paintAction(action))
	}
}

func (r renderer) bucketTarget(scope resourceScope) string {
	return "bucket " + r.paintBucket(scope.bucket)
}

func (r renderer) objectTarget(scope resourceScope) string {
	target := r.bucketTarget(scope)
	if scope.path == "" || scope.path == "*" {
		return target
	}
	return target + " path " + r.paintPath(scope.path)
}

func (r renderer) paintActionMeaning(value string) string {
	return r.paintWords(value, "1;33")
}

func (s resourceScope) supportsBucket() bool {
	return s.kind == resourceScopeBucketOnly || s.kind == resourceScopeBucketAndObjects
}

func (s resourceScope) supportsObjects() bool {
	return s.kind == resourceScopeObjectOnly || s.kind == resourceScopeBucketAndObjects
}
