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

package etcd

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/minio/minio/cmd/config"
	"github.com/minio/minio/pkg/env"
	xnet "github.com/minio/minio/pkg/net"
)

const (
	// Default values used while communicating with etcd.
	defaultDialTimeout   = 30 * time.Second
	defaultDialKeepAlive = 30 * time.Second
)

// etcd environment values
const (
	Endpoints     = "endpoints"
	CoreDNSPrefix = "coredns_prefix"
	ClientCert    = "client_cert"
	ClientCertKey = "client_cert_key"

	EnvEtcdState         = "MINIO_ETCD_STATE"
	EnvEtcdEndpoints     = "MINIO_ETCD_ENDPOINTS"
	EnvEtcdCoreDNSPrefix = "MINIO_ETCD_COREDNS_PREFIX"
	EnvEtcdClientCert    = "MINIO_ETCD_CLIENT_CERT"
	EnvEtcdClientCertKey = "MINIO_ETCD_CLIENT_CERT_KEY"
)

// DefaultKVS - default KV settings for etcd.
var (
	DefaultKVS = config.KVS{
		config.State:   config.StateOff,
		config.Comment: "This is a default etcd configuration, application only in federated setups",
		Endpoints:      "",
		CoreDNSPrefix:  "/skydns",
		ClientCert:     "",
		ClientCertKey:  "",
	}
)

// Config - server etcd config.
type Config struct {
	Enabled       bool   `json:"enabled"`
	CoreDNSPrefix string `json:"coreDNSPrefix"`
	clientv3.Config
}

// New - initialize new etcd client.
func New(cfg Config) (*clientv3.Client, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	return clientv3.New(cfg.Config)
}

// LookupConfig - Initialize new etcd config.
func LookupConfig(kv config.KVS, rootCAs *x509.CertPool) (Config, error) {
	cfg := Config{}
	if err := config.CheckValidKeys(config.EtcdSubSys, kv, DefaultKVS); err != nil {
		return cfg, err
	}

	stateBool, err := config.ParseBool(env.Get(EnvEtcdState, kv.Get(config.State)))
	if err != nil {
		return cfg, err
	}

	endpoints := env.Get(EnvEtcdEndpoints, kv.Get(Endpoints))
	if stateBool && len(endpoints) == 0 {
		return cfg, config.Error("'endpoints' key cannot be empty if you wish to enable etcd")
	}

	if len(endpoints) == 0 {
		return cfg, nil
	}

	cfg.Enabled = true
	etcdEndpoints := strings.Split(endpoints, config.ValueSeparator)

	var etcdSecure bool
	for _, endpoint := range etcdEndpoints {
		if endpoint == "" {
			continue
		}
		u, err := xnet.ParseURL(endpoint)
		if err != nil {
			return cfg, err
		}
		// If one of the endpoint is https, we will use https directly.
		etcdSecure = etcdSecure || u.Scheme == "https"
	}

	cfg.DialTimeout = defaultDialTimeout
	cfg.DialKeepAliveTime = defaultDialKeepAlive
	cfg.Endpoints = etcdEndpoints
	cfg.CoreDNSPrefix = env.Get(EnvEtcdCoreDNSPrefix, kv.Get(CoreDNSPrefix))
	if etcdSecure {
		cfg.TLS = &tls.Config{
			RootCAs: rootCAs,
		}
		// This is only to support client side certificate authentication
		// https://coreos.com/etcd/docs/latest/op-guide/security.html
		etcdClientCertFile := env.Get(EnvEtcdClientCert, kv.Get(ClientCert))
		etcdClientCertKey := env.Get(EnvEtcdClientCertKey, kv.Get(ClientCertKey))
		if etcdClientCertFile != "" && etcdClientCertKey != "" {
			cfg.TLS.GetClientCertificate = func(unused *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert, err := tls.LoadX509KeyPair(etcdClientCertFile, etcdClientCertKey)
				return &cert, err
			}
		}
	}
	return cfg, nil
}
