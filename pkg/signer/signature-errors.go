package signer

import (
	"encoding/xml"
	"net/http"
)

// SignatureErr - signer struct.
type SignatureErr struct {
	XMLName        xml.Name `xml:"Error" json:"-"`
	Code           string
	Message        string
	Key            string
	BucketName     string
	Resource       string
	RequestID      string `xml:"RequestId"`
	HostID         string `xml:"HostId"`
	HTTPStatusCode int    `xml:"-" json:"-"`
}

func (e *SignatureErr) Error() string {
	return e.Message
}

// List of signature related errors.
var (
	InvalidAccessKeyID = &SignatureErr{
		Code:           "InvalidAccessKeyId",
		Message:        "The access key ID you provided does not exist in our records.",
		HTTPStatusCode: http.StatusForbidden,
	}
	SignatureDoesNotMatch = &SignatureErr{
		Code:           "SignatureDoesNotMatch",
		Message:        "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
		HTTPStatusCode: http.StatusForbidden,
	}
	TokenDoesNotMatch = &SignatureErr{
		Code:           "TokenDoesNotMatch",
		Message:        "The request token we calculated does not match the token you provided. Check your key and signing method.",
		HTTPStatusCode: http.StatusForbidden,
	}
	MissingToken = &SignatureErr{
		Code:           "MissingToken",
		Message:        "The request token is missing.",
		HTTPStatusCode: http.StatusForbidden,
	}
	InvalidQueryParams = &SignatureErr{
		Code:           "AuthorizationQueryParametersError",
		Message:        "Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.",
		HTTPStatusCode: http.StatusBadRequest,
	}
	MalformedExpires = &SignatureErr{
		Code:           "AuthorizationQueryParametersError",
		Message:        "X-Amz-Expires should be a number",
		HTTPStatusCode: http.StatusBadRequest,
	}
	ExpiredPresignRequest = &SignatureErr{
		Code:           "AccessDenied",
		Message:        "Request has expired",
		HTTPStatusCode: http.StatusForbidden,
	}
	AuthHeaderEmpty = &SignatureErr{
		Code:           "InvalidArgument",
		Message:        "Authorization header is invalid -- one and only one ' ' (space) required.",
		HTTPStatusCode: http.StatusBadRequest,
	}
	SignatureVersionNotSupported = &SignatureErr{
		Code:           "InvalidRequest",
		Message:        "The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.",
		HTTPStatusCode: http.StatusBadRequest,
	}
	MissingFields = &SignatureErr{
		Code:           "MissingFields",
		Message:        "Missing fields in request.",
		HTTPStatusCode: http.StatusBadRequest,
	}
	MissingCredTag = &SignatureErr{
		Code:           "InvalidRequest",
		Message:        "Missing Credential field for this request.",
		HTTPStatusCode: http.StatusBadRequest,
	}
	// FIXME: Should contain the invalid param set as seen in https://github.com/minio/minio/issues/2385.
	// right Description:   "Error parsing the X-Amz-Credential parameter; incorrect service \"s4\". This endpoint belongs to \"s3\".".
	// Need changes to make sure variable messages can be constructed.
	InvalidService = &SignatureErr{
		Code:           "AuthorizationQueryParametersError",
		Message:        "Error parsing the X-Amz-Credential parameter; incorrect service. This endpoint belongs to \"s3\".",
		HTTPStatusCode: http.StatusBadRequest,
	}
	// FIXME: Should contain the invalid param set as seen in https://github.com/minio/minio/issues/2385.
	// right Description:    "Error parsing the X-Amz-Credential parameter; incorrect date format \"%s\". This date in the credential must be in the format \"yyyyMMdd\".",
	// Need changes to make sure variable messages can be constructed.
	MalformedCredentialDate = &SignatureErr{
		Code:           "AuthorizationQueryParametersError",
		Message:        "Error parsing the X-Amz-Credential parameter; incorrect date format \"%s\". This date in the credential must be in the format \"yyyyMMdd\".",
		HTTPStatusCode: http.StatusBadRequest,
	}
	// FIXME: Should contain the invalid param set as seen in https://github.com/minio/minio/issues/2385.
	// right Description:    "Error parsing the X-Amz-Credential parameter; the region 'us-east-' is wrong; expecting 'us-east-1'".
	// Need changes to make sure variable messages can be constructed.
	MalformedCredentialRegion = &SignatureErr{
		Code:           "AuthorizationQueryParametersError",
		Message:        "Error parsing the X-Amz-Credential parameter; the region is wrong;",
		HTTPStatusCode: http.StatusBadRequest,
	}
	CredMalformed = &SignatureErr{
		Code:           "AuthorizationQueryParametersError",
		Message:        "Error parsing the X-Amz-Credential parameter; the Credential is mal-formed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".",
		HTTPStatusCode: http.StatusBadRequest,
	}
	// FIXME: Should contain the invalid param set as seen in https://github.com/minio/minio/issues/2385.
	// Description:   "Error parsing the X-Amz-Credential parameter; incorrect terminal "aws4_reque". This endpoint uses "aws4_request".
	// Need changes to make sure variable messages can be constructed.
	InvalidRequestVersion = &SignatureErr{
		Code:           "AuthorizationQueryParametersError",
		Message:        "Error parsing the X-Amz-Credential parameter; incorrect terminal. This endpoint uses \"aws4_request\".",
		HTTPStatusCode: http.StatusBadRequest,
	}
	MissingSignTag = &SignatureErr{
		Code:           "AccessDenied",
		Message:        "Signature header missing Signature field.",
		HTTPStatusCode: http.StatusBadRequest,
	}
	MissingSignHeadersTag = &SignatureErr{
		Code:           "InvalidArgument",
		Message:        "Signature header missing SignedHeaders field.",
		HTTPStatusCode: http.StatusBadRequest,
	}
	InvalidQuerySignatureAlgo = &SignatureErr{
		Code:           "AuthorizationQueryParametersError",
		Message:        "X-Amz-Algorithm only supports \"AWS4-HMAC-SHA256\".",
		HTTPStatusCode: http.StatusBadRequest,
	}
	MalformedPresignedDate = &SignatureErr{
		Code:           "AuthorizationQueryParametersError",
		Message:        "X-Amz-Date must be in the ISO8601 Long Format \"yyyyMMdd'T'HHmmss'Z'\"",
		HTTPStatusCode: http.StatusBadRequest,
	}
	NegativeExpires = &SignatureErr{
		Code:           "AuthorizationQueryParametersError",
		Message:        "X-Amz-Expires must be non-negative",
		HTTPStatusCode: http.StatusBadRequest,
	}
	UnsignedHeaders = &SignatureErr{
		Code:           "AccessDenied",
		Message:        "There were headers present in the request which were not signed",
		HTTPStatusCode: http.StatusBadRequest,
	}
	AccessDenied = &SignatureErr{
		Code:           "AccessDenied",
		Message:        "Access Denied.",
		HTTPStatusCode: http.StatusForbidden,
	}
	ContentSHA256Mismatch = &SignatureErr{
		Code:           "XAmzContentSHA256Mismatch",
		Message:        "The provided 'x-amz-content-sha256' header does not match what was computed.",
		HTTPStatusCode: http.StatusBadRequest,
	}
	BadDigest = &SignatureErr{
		Code:           "BadDigest",
		Message:        "The Content-Md5 you specified did not match what we received.",
		HTTPStatusCode: http.StatusBadRequest,
	}
	InvalidRegion = &SignatureErr{
		Code:           "InvalidRegion",
		Message:        "Region does not match.",
		HTTPStatusCode: http.StatusBadRequest,
	}
	RequestNotReadyYet = &SignatureErr{
		Code:           "AccessDenied",
		Message:        "Request is not valid yet",
		HTTPStatusCode: http.StatusForbidden,
	}
	MissingDateHeader = &SignatureErr{
		Code:           "AccessDenied",
		Message:        "AWS authentication requires a valid Date or x-amz-date header",
		HTTPStatusCode: http.StatusBadRequest,
	}
	MalformedDate = &SignatureErr{
		Code:           "MalformedDate",
		Message:        "Invalid date format header, expected to be in ISO8601, RFC1123 or RFC1123Z time format.",
		HTTPStatusCode: http.StatusBadRequest,
	}
	InvalidRequest = &SignatureErr{
		Code:           "InvalidRequest",
		Message:        "Invalid Request",
		HTTPStatusCode: http.StatusBadRequest,
	}
	MaximumExpires = &SignatureErr{
		Code:           "AuthorizationQueryParametersError",
		Message:        "X-Amz-Expires must be less than a week (in seconds); that is, the given X-Amz-Expires must be less than 604800 seconds",
		HTTPStatusCode: http.StatusBadRequest,
	}
)
