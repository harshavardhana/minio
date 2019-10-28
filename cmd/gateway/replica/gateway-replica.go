/*
 * MinIO Cloud Storage, (C) 2019 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package replica

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/minio/cli"
	miniogo "github.com/minio/minio-go/v6"
	"github.com/minio/minio-go/v6/pkg/credentials"
	minio "github.com/minio/minio/cmd"

	"github.com/minio/minio-go/v6/pkg/encrypt"
	"github.com/minio/minio-go/v6/pkg/s3utils"
	"github.com/minio/minio/cmd/logger"
	"github.com/minio/minio/pkg/auth"
	"github.com/minio/minio/pkg/policy"
	"github.com/minio/minio/pkg/sync/errgroup"
)

const (
	replicaBackend = "replica"
)

func init() {
	const replicaGatewayTemplate = `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} {{if .VisibleFlags}}[FLAGS]{{end}} ENDPOINT1 ENDPOINT2 ENDPOINT3...
{{if .VisibleFlags}}
FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}{{end}}
ENDPOINT:
  Minimum 2 difference endpoints are needed

ENVIRONMENT VARIABLES:
  ACCESS:
     MINIO_ACCESS_KEY: Username or access key of S3 storage.
     MINIO_SECRET_KEY: Password or secret key of S3 storage.

  BROWSER:
     MINIO_BROWSER: To disable web browser access, set this value to "off".

  DOMAIN:
     MINIO_DOMAIN: To enable virtual-host-style requests, set this value to MinIO host domain name.

  CACHE:
     MINIO_CACHE_DRIVES: List of mounted drives or directories delimited by ";".
     MINIO_CACHE_EXCLUDE: List of cache exclusion patterns delimited by ";".
     MINIO_CACHE_EXPIRY: Cache expiry duration in days.
     MINIO_CACHE_QUOTA: Maximum permitted usage of the cache in percentage (0-100).

  LOGGER:
     MINIO_LOGGER_HTTP_ENDPOINT: HTTP endpoint URL to log all incoming requests.

EXAMPLES:
  1. Start minio gateway server for AWS S3 backend.
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_ACCESS_KEY{{.AssignmentOperator}}accesskey
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_SECRET_KEY{{.AssignmentOperator}}secretkey
     {{.Prompt}} {{.HelpName}}

  2. Start minio gateway server for S3 backend on custom endpoint.
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_ACCESS_KEY{{.AssignmentOperator}}Q3AM3UQ867SPQQA43P2F
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_SECRET_KEY{{.AssignmentOperator}}zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG
     {{.Prompt}} {{.HelpName}} https://play.min.io:9000

  3. Start minio gateway server for AWS S3 backend logging all requests to http endpoint.
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_ACCESS_KEY{{.AssignmentOperator}}Q3AM3UQ867SPQQA43P2F
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_SECRET_KEY{{.AssignmentOperator}}zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_LOGGER_HTTP_ENDPOINT{{.AssignmentOperator}}"http://localhost:8000/"
     {{.Prompt}} {{.HelpName}} https://play.min.io:9000

  4. Start minio gateway server for AWS S3 backend with edge caching enabled.
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_ACCESS_KEY{{.AssignmentOperator}}accesskey
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_SECRET_KEY{{.AssignmentOperator}}secretkey
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_DRIVES{{.AssignmentOperator}}"/mnt/drive1;/mnt/drive2;/mnt/drive3;/mnt/drive4"
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_EXCLUDE{{.AssignmentOperator}}"bucket1/*;*.png"
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_EXPIRY{{.AssignmentOperator}}40
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_QUOTA{{.AssignmentOperator}}80
     {{.Prompt}} {{.HelpName}}

  4. Start minio gateway server for AWS S3 backend using AWS environment variables.
     NOTE: The access and secret key in this case will authenticate with MinIO instead
     of AWS and AWS envs will be used to authenticate to AWS S3.
     {{.Prompt}} {{.EnvVarSetCommand}} AWS_ACCESS_KEY_ID{{.AssignmentOperator}}aws_access_key
     {{.Prompt}} {{.EnvVarSetCommand}} AWS_SECRET_ACCESS_KEY{{.AssignmentOperator}}aws_secret_key
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_ACCESS_KEY{{.AssignmentOperator}}accesskey
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_SECRET_KEY{{.AssignmentOperator}}secretkey
     {{.Prompt}} {{.HelpName}}
`

	minio.RegisterGatewayCommand(cli.Command{
		Name:               replicaBackend,
		Usage:              "Active/Active replication gateway to multiple compatible sites",
		Action:             replicaGatewayMain,
		CustomHelpTemplate: replicaGatewayTemplate,
		HideHelpCommand:    true,
	})
}

// Handler for 'minio gateway s3' command line.
func replicaGatewayMain(ctx *cli.Context) {
	args := ctx.Args()
	if !ctx.Args().Present() {
		args = cli.Args{"https://s3.amazonaws.com"}
	}

	// Validate gateway arguments.
	logger.FatalIf(minio.ValidateGatewayArguments(ctx.GlobalString("address"), args.First()), "Invalid argument")

	// Start the gateway..
	minio.StartGateway(ctx, &Replica{args.Tail()})
}

// Replica implements active/active replicated gateway
type Replica struct {
	hosts []string
}

// Name implements Gateway interface.
func (g *Replica) Name() string {
	return replicaBackend
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz01234569"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// randString generates random names and prepends them with a known prefix.
func randString(n int, src rand.Source, prefix string) string {
	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax letters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return prefix + string(b[0:30-len(prefix)])
}

// newS3 - Initializes a new client by auto probing S3 server signature.
func newS3(urlStr string) (*miniogo.Core, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, errors.New("invalid arguments")
	}

	password, ok := u.User.Password()
	if !ok {
		return nil, errors.New("invalid arguments")
	}

	options := miniogo.Options{
		Creds:        credentials.NewStaticV4(u.User.Username(), password, ""),
		Secure:       u.Scheme == "https",
		Region:       s3utils.GetRegionFromURL(*u),
		BucketLookup: miniogo.BucketLookupAuto,
	}

	clnt, err := miniogo.NewWithOptions(u.Host, &options)
	if err != nil {
		return nil, err
	}

	// Set custom transport
	clnt.SetCustomTransport(minio.NewCustomHTTPTransport())

	probeBucketName := randString(60, rand.NewSource(time.Now().UnixNano()), "probe-bucket-sign-")

	// Check if the provided keys are valid.
	if _, err = clnt.BucketExists(probeBucketName); err != nil {
		if miniogo.ToErrorResponse(err).Code != "AccessDenied" {
			return nil, err
		}
	}

	return &miniogo.Core{Client: clnt}, nil
}

// NewGatewayLayer returns s3 ObjectLayer.
func (g *Replica) NewGatewayLayer(creds auth.Credentials) (minio.ObjectLayer, error) {
	s := replicaObjects{
		multipartUploadIDMap: make(map[string][]string),
	}
	// creds are ignored here, since S3 gateway implements chaining all credentials.
	for _, host := range g.hosts {
		clnt, err := newS3(host)
		if err != nil {
			return nil, err
		}
		s.Clients = append(s.Clients, clnt)
	}
	return &s, nil
}

// Production - s3 gateway is production ready.
func (g *Replica) Production() bool {
	return true
}

// replicaObjects implements gateway for MinIO and S3 compatible object storage servers.
type replicaObjects struct {
	minio.GatewayUnsupported
	Clients              []*miniogo.Core
	multipartUploadIDMap map[string][]string
	rwMutex              sync.RWMutex
}

// Shutdown saves any gateway metadata to disk
// if necessary and reload upon next restart.
func (l *replicaObjects) Shutdown(ctx context.Context) error {
	return nil
}

// StorageInfo is not relevant to S3 backend.
func (l *replicaObjects) StorageInfo(ctx context.Context) (si minio.StorageInfo) {
	return si
}

// MakeBucket creates a new container on S3 backend.
func (l *replicaObjects) MakeBucketWithLocation(ctx context.Context, bucket, location string) error {
	// Verify if bucket name is valid.
	// We are using a separate helper function here to validate bucket
	// names instead of IsValidBucketName() because there is a possibility
	// that certains users might have buckets which are non-DNS compliant
	// in us-east-1 and we might severely restrict them by not allowing
	// access to these buckets.
	// Ref - http://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html
	if s3utils.CheckValidBucketName(bucket) != nil {
		return minio.BucketNameInvalid{Bucket: bucket}
	}

	for _, clnt := range l.Clients {
		if err := clnt.MakeBucket(bucket, location); err != nil {
			return minio.ErrorRespToObjectError(err, bucket)
		}
	}
	return nil
}

// GetBucketInfo gets bucket metadata..
func (l *replicaObjects) GetBucketInfo(ctx context.Context, bucket string) (bi minio.BucketInfo, e error) {
	buckets, err := l.Clients[0].ListBuckets()
	if err != nil {
		// Listbuckets may be disallowed, proceed to check if
		// bucket indeed exists, if yes return success.
		var ok bool
		if ok, err = l.Clients[0].BucketExists(bucket); err != nil {
			return bi, minio.ErrorRespToObjectError(err, bucket)
		}
		if !ok {
			return bi, minio.BucketNotFound{Bucket: bucket}
		}
		return minio.BucketInfo{
			Name:    bi.Name,
			Created: time.Now().UTC(),
		}, nil
	}

	for _, bi := range buckets {
		if bi.Name != bucket {
			continue
		}

		return minio.BucketInfo{
			Name:    bi.Name,
			Created: bi.CreationDate,
		}, nil
	}

	return bi, minio.BucketNotFound{Bucket: bucket}
}

// ListBuckets lists all S3 buckets
func (l *replicaObjects) ListBuckets(ctx context.Context) ([]minio.BucketInfo, error) {
	buckets, err := l.Clients[0].ListBuckets()
	if err != nil {
		return nil, minio.ErrorRespToObjectError(err)
	}

	b := make([]minio.BucketInfo, len(buckets))
	for i, bi := range buckets {
		b[i] = minio.BucketInfo{
			Name:    bi.Name,
			Created: bi.CreationDate,
		}
	}

	return b, err
}

// DeleteBucket deletes a bucket on S3
func (l *replicaObjects) DeleteBucket(ctx context.Context, bucket string) error {
	for _, clnt := range l.Clients {
		err := clnt.RemoveBucket(bucket)
		if err != nil {
			return minio.ErrorRespToObjectError(err, bucket)
		}
	}
	return nil
}

// ListObjects lists all blobs in S3 bucket filtered by prefix
func (l *replicaObjects) ListObjects(ctx context.Context, bucket string, prefix string, marker string, delimiter string, maxKeys int) (loi minio.ListObjectsInfo, e error) {
	result, err := l.Clients[0].ListObjects(bucket, prefix, marker, delimiter, maxKeys)
	if err != nil {
		return loi, minio.ErrorRespToObjectError(err, bucket)
	}

	return minio.FromMinioClientListBucketResult(bucket, result), nil
}

// ListObjectsV2 lists all blobs in S3 bucket filtered by prefix
func (l *replicaObjects) ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int, fetchOwner bool, startAfter string) (loi minio.ListObjectsV2Info, e error) {

	result, err := l.Clients[0].ListObjectsV2(bucket, prefix, continuationToken, fetchOwner, delimiter, maxKeys, startAfter)
	if err != nil {
		return loi, minio.ErrorRespToObjectError(err, bucket)
	}

	return minio.FromMinioClientListBucketV2Result(bucket, result), nil
}

// GetObjectNInfo - returns object info and locked object ReadCloser
func (l *replicaObjects) GetObjectNInfo(ctx context.Context, bucket, object string, rs *minio.HTTPRangeSpec, h http.Header, lockType minio.LockType, opts minio.ObjectOptions) (gr *minio.GetObjectReader, err error) {
	var objInfo minio.ObjectInfo
	objInfo, err = l.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		return nil, minio.ErrorRespToObjectError(err, bucket, object)
	}

	var startOffset, length int64
	startOffset, length, err = rs.GetOffsetLength(objInfo.Size)
	if err != nil {
		return nil, minio.ErrorRespToObjectError(err, bucket, object)
	}

	pr, pw := io.Pipe()
	go func() {
		err := l.GetObject(ctx, bucket, object, startOffset, length, pw, objInfo.ETag, opts)
		pw.CloseWithError(err)
	}()
	// Setup cleanup function to cause the above go-routine to
	// exit in case of partial read
	pipeCloser := func() { pr.Close() }
	return minio.NewGetObjectReaderFromReader(pr, objInfo, opts.CheckCopyPrecondFn, pipeCloser)
}

// GetObject reads an object from S3. Supports additional
// parameters like offset and length which are synonymous with
// HTTP Range requests.
//
// startOffset indicates the starting read location of the object.
// length indicates the total length of the object.
func (l *replicaObjects) GetObject(ctx context.Context, bucket string, key string, startOffset int64, length int64, writer io.Writer, etag string, o minio.ObjectOptions) error {
	if length < 0 && length != -1 {
		return minio.ErrorRespToObjectError(minio.InvalidRange{}, bucket, key)
	}

	opts := miniogo.GetObjectOptions{}
	opts.ServerSideEncryption = o.ServerSideEncryption

	if startOffset >= 0 && length >= 0 {
		if err := opts.SetRange(startOffset, startOffset+length-1); err != nil {
			return minio.ErrorRespToObjectError(err, bucket, key)
		}
	}
	object, _, _, err := l.Clients[0].GetObject(bucket, key, opts)
	if err != nil {
		return minio.ErrorRespToObjectError(err, bucket, key)
	}
	defer object.Close()
	if _, err := io.Copy(writer, object); err != nil {
		return minio.ErrorRespToObjectError(err, bucket, key)
	}
	return nil
}

// GetObjectInfo reads object info and replies back ObjectInfo
func (l *replicaObjects) GetObjectInfo(ctx context.Context, bucket string, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	oi, err := l.Clients[0].StatObject(bucket, object, miniogo.StatObjectOptions{
		GetObjectOptions: miniogo.GetObjectOptions{
			ServerSideEncryption: opts.ServerSideEncryption,
		},
	})
	if err != nil {
		return minio.ObjectInfo{}, minio.ErrorRespToObjectError(err, bucket, object)
	}

	return minio.FromMinioClientObjectInfo(bucket, oi), nil
}

// PutObject creates a new object with the incoming data,
func (l *replicaObjects) PutObject(ctx context.Context, bucket string, object string, r *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	data := r.Reader

	readers, writers := pipeN(len(l.Clients))
	writer := &multiWriter{writers}

	oinfos := make([]miniogo.ObjectInfo, len(l.Clients))
	g := errgroup.WithNErrs(len(l.Clients))
	for index := range l.Clients {
		index := index
		g.Go(func() error {
			var perr error
			oinfos[index], perr = l.Clients[index].PutObject(bucket, object, readers[index], data.Size(), data.MD5Base64String(), data.SHA256HexString(), minio.ToMinioClientMetadata(opts.UserDefined), opts.ServerSideEncryption)
			return perr
		}, index)
	}

	io.CopyN(writer, data, data.Size())
	writer.Close()

	for _, err = range g.Wait() {
		if err != nil {
			return objInfo, minio.ErrorRespToObjectError(err, bucket, object)
		}
	}

	oi := oinfos[0]
	// On success, populate the key & metadata so they are present in the notification
	oi.Key = object
	oi.Metadata = minio.ToMinioClientObjectInfoMetadata(opts.UserDefined)

	return minio.FromMinioClientObjectInfo(bucket, oi), nil
}

// CopyObject copies an object from source bucket to a destination bucket.
func (l *replicaObjects) CopyObject(ctx context.Context, srcBucket string, srcObject string, dstBucket string, dstObject string, srcInfo minio.ObjectInfo, srcOpts, dstOpts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	if srcOpts.CheckCopyPrecondFn != nil && srcOpts.CheckCopyPrecondFn(srcInfo, "") {
		return minio.ObjectInfo{}, minio.PreConditionFailed{}
	}
	// Set this header such that following CopyObject() always sets the right metadata on the destination.
	// metadata input is already a trickled down value from interpreting x-amz-metadata-directive at
	// handler layer. So what we have right now is supposed to be applied on the destination object anyways.
	// So preserve it by adding "REPLACE" directive to save all the metadata set by CopyObject API.
	srcInfo.UserDefined["x-amz-metadata-directive"] = "REPLACE"
	srcInfo.UserDefined["x-amz-copy-source-if-match"] = srcInfo.ETag
	header := make(http.Header)
	if srcOpts.ServerSideEncryption != nil {
		encrypt.SSECopy(srcOpts.ServerSideEncryption).Marshal(header)
	}

	if dstOpts.ServerSideEncryption != nil {
		dstOpts.ServerSideEncryption.Marshal(header)
	}
	for k, v := range header {
		srcInfo.UserDefined[k] = v[0]
	}

	for _, clnt := range l.Clients {
		if _, err = clnt.CopyObject(srcBucket, srcObject, dstBucket, dstObject, srcInfo.UserDefined); err != nil {
			return objInfo, minio.ErrorRespToObjectError(err, srcBucket, srcObject)
		}
	}
	return l.GetObjectInfo(ctx, dstBucket, dstObject, dstOpts)
}

// DeleteObject deletes a blob in bucket
func (l *replicaObjects) DeleteObject(ctx context.Context, bucket string, object string) error {
	for _, clnt := range l.Clients {
		if err := clnt.RemoveObject(bucket, object); err != nil {
			return minio.ErrorRespToObjectError(err, bucket, object)
		}
	}

	return nil
}

func (l *replicaObjects) DeleteObjects(ctx context.Context, bucket string, objects []string) ([]error, error) {
	errs := make([]error, len(objects))
	for idx, object := range objects {
		errs[idx] = l.DeleteObject(ctx, bucket, object)
	}
	return errs, nil
}

// ListMultipartUploads lists all multipart uploads.
func (l *replicaObjects) ListMultipartUploads(ctx context.Context, bucket string, prefix string, keyMarker string, uploadIDMarker string, delimiter string, maxUploads int) (lmi minio.ListMultipartsInfo, e error) {
	result, err := l.Clients[0].ListMultipartUploads(bucket, prefix, keyMarker, uploadIDMarker, delimiter, maxUploads)
	if err != nil {
		return lmi, err
	}

	return minio.FromMinioClientListMultipartsInfo(result), nil
}

// NewMultipartUpload upload object in multiple parts
func (l *replicaObjects) NewMultipartUpload(ctx context.Context, bucket string, object string, o minio.ObjectOptions) (string, error) {
	l.rwMutex.Lock()
	defer l.rwMutex.Unlock()

	// Create PutObject options
	opts := miniogo.PutObjectOptions{UserMetadata: o.UserDefined, ServerSideEncryption: o.ServerSideEncryption}
	uploadID := minio.MustGetUUID()
	for _, clnt := range l.Clients {
		id, err := clnt.NewMultipartUpload(bucket, object, opts)
		if err != nil {
			// Abort any failed uploads to one of the replicas
			clnt.AbortMultipartUpload(bucket, object, uploadID)
			return uploadID, minio.ErrorRespToObjectError(err, bucket, object)
		}
		l.multipartUploadIDMap[uploadID] = append(l.multipartUploadIDMap[uploadID], id)

	}
	return uploadID, nil
}

func pipeN(count int) (readers []io.ReadCloser, writers []io.WriteCloser) {
	readers = make([]io.ReadCloser, count)
	writers = make([]io.WriteCloser, count)
	for i := 0; i < count; i++ {
		readers[i], writers[i] = io.Pipe()
	}
	return readers, writers
}

type multiWriter struct {
	writers []io.WriteCloser
}

func (t *multiWriter) Close() error {
	for index := range t.writers {
		t.writers[index].Close()
	}
	return nil
}

func (t *multiWriter) Write(p []byte) (n int, err error) {
	g := errgroup.WithNErrs(len(t.writers))
	for index := range t.writers {
		index := index
		g.Go(func() error {
			m, werr := t.writers[index].Write(p)
			if werr != nil {
				return werr
			}
			if m != len(p) {
				return io.ErrShortWrite
			}
			return nil
		}, index)
	}
	for _, err = range g.Wait() {
		if err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

// PutObjectPart puts a part of object in bucket
func (l *replicaObjects) PutObjectPart(ctx context.Context, bucket string, object string, uploadID string, partID int, r *minio.PutObjReader, opts minio.ObjectOptions) (pi minio.PartInfo, e error) {
	data := r.Reader

	readers, writers := pipeN(len(l.Clients))

	l.rwMutex.RLock()
	defer l.rwMutex.RUnlock()
	uploadIDs, ok := l.multipartUploadIDMap[uploadID]
	if !ok {
		return pi, minio.InvalidUploadID{
			Bucket:   bucket,
			Object:   object,
			UploadID: uploadID,
		}
	}

	pinfos := make([]miniogo.ObjectPart, len(l.Clients))
	g := errgroup.WithNErrs(len(l.Clients))
	for index := range l.Clients {
		index := index
		g.Go(func() error {
			var err error
			pinfos[index], err = l.Clients[index].PutObjectPart(bucket, object, uploadIDs[index], partID, readers[index], data.Size(), data.MD5Base64String(), data.SHA256HexString(), opts.ServerSideEncryption)
			readers[index].Close()
			return err
		}, index)
	}

	writer := &multiWriter{writers}
	io.CopyN(writer, data, data.Size())
	writer.Close()

	for _, err := range g.Wait() {
		if err != nil {
			return pi, minio.ErrorRespToObjectError(err, bucket, object)
		}
	}

	return minio.FromMinioClientObjectPart(pinfos[0]), nil
}

// CopyObjectPart creates a part in a multipart upload by copying
// existing object or a part of it.
func (l *replicaObjects) CopyObjectPart(ctx context.Context, srcBucket, srcObject, destBucket, destObject, uploadID string,
	partID int, startOffset, length int64, srcInfo minio.ObjectInfo, srcOpts, dstOpts minio.ObjectOptions) (p minio.PartInfo, err error) {
	if srcOpts.CheckCopyPrecondFn != nil && srcOpts.CheckCopyPrecondFn(srcInfo, "") {
		return minio.PartInfo{}, minio.PreConditionFailed{}
	}
	srcInfo.UserDefined = map[string]string{
		"x-amz-copy-source-if-match": srcInfo.ETag,
	}
	header := make(http.Header)
	if srcOpts.ServerSideEncryption != nil {
		encrypt.SSECopy(srcOpts.ServerSideEncryption).Marshal(header)
	}

	if dstOpts.ServerSideEncryption != nil {
		dstOpts.ServerSideEncryption.Marshal(header)
	}
	for k, v := range header {
		srcInfo.UserDefined[k] = v[0]
	}

	l.rwMutex.RLock()
	defer l.rwMutex.RUnlock()

	uploadIDs, ok := l.multipartUploadIDMap[uploadID]
	if !ok {
		return p, minio.InvalidUploadID{
			Bucket:   srcBucket,
			Object:   srcObject,
			UploadID: uploadID,
		}
	}

	pinfos := make([]miniogo.CompletePart, len(l.Clients))

	g := errgroup.WithNErrs(len(l.Clients))
	for index := range l.Clients {
		index := index
		g.Go(func() error {
			var err error
			pinfos[index], err = l.Clients[index].CopyObjectPart(srcBucket, srcObject, destBucket, destObject,
				uploadIDs[index], partID, startOffset, length, srcInfo.UserDefined)
			return err
		}, index)
	}

	for _, err := range g.Wait() {
		if err != nil {
			return p, minio.ErrorRespToObjectError(err, srcBucket, srcObject)
		}
	}
	p.PartNumber = pinfos[0].PartNumber
	p.ETag = pinfos[0].ETag
	return p, nil
}

// ListObjectParts returns all object parts for specified object in specified bucket
func (l *replicaObjects) ListObjectParts(ctx context.Context, bucket string, object string, uploadID string, partNumberMarker int, maxParts int, opts minio.ObjectOptions) (lpi minio.ListPartsInfo, e error) {
	l.rwMutex.RLock()
	defer l.rwMutex.RUnlock()

	uploadIDs, ok := l.multipartUploadIDMap[uploadID]
	if !ok {
		return lpi, minio.InvalidUploadID{
			Bucket:   bucket,
			Object:   object,
			UploadID: uploadID,
		}
	}
	for index, id := range uploadIDs {
		result, err := l.Clients[index].ListObjectParts(bucket, object, id, partNumberMarker, maxParts)
		if err != nil {
			return lpi, minio.ErrorRespToObjectError(err, bucket, object)
		}
		lpi = minio.FromMinioClientListPartsInfo(result)
		break
	}
	return lpi, nil
}

// AbortMultipartUpload aborts a ongoing multipart upload
func (l *replicaObjects) AbortMultipartUpload(ctx context.Context, bucket string, object string, uploadID string) error {
	l.rwMutex.Lock()
	defer l.rwMutex.Unlock()
	uploadIDs, ok := l.multipartUploadIDMap[uploadID]
	if !ok {
		return minio.InvalidUploadID{
			Bucket:   bucket,
			Object:   object,
			UploadID: uploadID,
		}
	}
	for index, id := range uploadIDs {
		if err := l.Clients[index].AbortMultipartUpload(bucket, object, id); err != nil {
			return minio.ErrorRespToObjectError(err, bucket, object)
		}
	}
	delete(l.multipartUploadIDMap, uploadID)
	return nil
}

// CompleteMultipartUpload completes ongoing multipart upload and finalizes object
func (l *replicaObjects) CompleteMultipartUpload(ctx context.Context, bucket string, object string, uploadID string, uploadedParts []minio.CompletePart, opts minio.ObjectOptions) (oi minio.ObjectInfo, err error) {
	l.rwMutex.Lock()
	defer l.rwMutex.Unlock()
	uploadIDs, ok := l.multipartUploadIDMap[uploadID]
	if !ok {
		return oi, minio.InvalidUploadID{
			Bucket:   bucket,
			Object:   object,
			UploadID: uploadID,
		}
	}

	var etag string
	for index, id := range uploadIDs {
		etag, err = l.Clients[index].CompleteMultipartUpload(bucket, object, id,
			minio.ToMinioClientCompleteParts(uploadedParts))
		if err != nil {
			return oi, minio.ErrorRespToObjectError(err, bucket, object)
		}
	}
	delete(l.multipartUploadIDMap, uploadID)
	return minio.ObjectInfo{Bucket: bucket, Name: object, ETag: etag}, nil
}

// SetBucketPolicy sets policy on bucket
func (l *replicaObjects) SetBucketPolicy(ctx context.Context, bucket string, bucketPolicy *policy.Policy) error {
	data, err := json.Marshal(bucketPolicy)
	if err != nil {
		// This should not happen.
		logger.LogIf(ctx, err)
		return minio.ErrorRespToObjectError(err, bucket)
	}

	for _, clnt := range l.Clients {
		if err := clnt.SetBucketPolicy(bucket, string(data)); err != nil {
			return minio.ErrorRespToObjectError(err, bucket)
		}
	}

	return nil
}

// GetBucketPolicy will get policy on bucket
func (l *replicaObjects) GetBucketPolicy(ctx context.Context, bucket string) (bucketPolicy *policy.Policy, err error) {
	for _, clnt := range l.Clients {
		data, err := clnt.GetBucketPolicy(bucket)
		if err != nil {
			return nil, minio.ErrorRespToObjectError(err, bucket)
		}
		bucketPolicy, err = policy.ParseConfig(strings.NewReader(data), bucket)
		if err != nil {
			return nil, minio.ErrorRespToObjectError(err, bucket)
		}
	}
	return bucketPolicy, nil
}

// DeleteBucketPolicy deletes all policies on bucket
func (l *replicaObjects) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	for _, clnt := range l.Clients {
		if err := clnt.SetBucketPolicy(bucket, ""); err != nil {
			return minio.ErrorRespToObjectError(err, bucket, "")
		}
	}
	return nil
}

// IsCompressionSupported returns whether compression is applicable for this layer.
func (l *replicaObjects) IsCompressionSupported() bool {
	return false
}

// IsEncryptionSupported returns whether server side encryption is implemented for this layer.
func (l *replicaObjects) IsEncryptionSupported() bool {
	return false
}
