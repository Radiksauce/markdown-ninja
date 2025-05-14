package certmanager

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/log/slogx"
	"github.com/bloom42/stdx-go/memorycache"
	"github.com/bloom42/stdx-go/set"
	"golang.org/x/crypto/acme/autocert"
	"markdown.ninja/cmd/mdninja-server/config"
	"markdown.ninja/pkg/kms"
	"markdown.ninja/pkg/services/websites"
)

type CertManager struct {
	db              db.DB
	autocertDomains set.Set[string]
	// the self-signed certificate used by default when client hello server name doesn't match any allowed domain
	defaultCertificate *tls.Certificate
	websitesService    websites.Service
	httpConfig         config.Http
	kms                *kms.Kms

	cache           *memorycache.Cache[string, *tls.Certificate]
	autocertManager *autocert.Manager
}

type cert struct {
	Key            string `db:"key"`
	EncryptedValue []byte `db:"encrypted_value"`
}

// Note that all hosts will be converted to Punycode via idna.Lookup.ToASCII so that
// Manager.GetCertificate can handle the Unicode IDN and mixedcase hosts correctly.
// Invalid hosts will be silently ignored.
func NewCertManager(db db.DB, kms *kms.Kms,
	autocertManager *autocert.Manager, websitesService websites.Service, httpConfig config.Http) (certManager *CertManager, err error) {

	selfSignedTlsCertificate, err := generateSelfSignedCert()
	if err != nil {
		return
	}

	autocertDomains := set.New[string]()
	autocertDomains.Insert(httpConfig.WebappDomain)
	autocertDomains.Insert(fmt.Sprintf("www.%s", httpConfig.WebappDomain))
	autocertDomains.Insert(httpConfig.WebsitesRootDomain)

	certsCache := memorycache.New(
		memorycache.WithCapacity[string, *tls.Certificate](10_000),
		memorycache.WithTTL[string, *tls.Certificate](1*time.Hour),
	)

	certManager = &CertManager{
		db:                 db,
		kms:                kms,
		autocertDomains:    autocertDomains,
		defaultCertificate: selfSignedTlsCertificate,
		autocertManager:    autocertManager,
		websitesService:    websitesService,
		httpConfig:         httpConfig,
		cache:              certsCache,
	}
	return certManager, nil
}

func (certManager *CertManager) isAllowedDomain(ctx context.Context, host string) bool {
	if certManager.autocertDomains.Contains(host) ||
		// allow subdomains for WebsitesRootDomain only 1 level deep
		(strings.HasSuffix(host, certManager.httpConfig.WebsitesRootDomain) &&
			strings.Count(host, ".") == (strings.Count(certManager.httpConfig.WebsitesRootDomain, ".")+1)) {
		return true
	}

	_, err := certManager.websitesService.FindWebsiteByDomain(ctx, certManager.db, host)
	if err == nil {
		return true
	}

	return false
}

func (certManager *CertManager) DefaultCertificate() *tls.Certificate {
	return certManager.defaultCertificate
}

func (certManager *CertManager) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if certManager.isAllowedDomain(context.Background(), clientHello.ServerName) {
		if cachedCert := certManager.cache.Get(clientHello.ServerName); cachedCert != nil {
			return cachedCert.Value(), nil
		}

		cert, err := certManager.autocertManager.GetCertificate(clientHello)
		if err != nil {
			return cert, err
		}

		certManager.cache.Set(clientHello.ServerName, cert, memorycache.DefaultTTL)
		return cert, nil
	}

	return certManager.DefaultCertificate(), nil
}

func (certManager *CertManager) Get(ctx context.Context, key string) ([]byte, error) {
	var cert cert
	logger := slogx.FromCtx(ctx)

	err := certManager.db.Get(ctx, &cert, "SELECT * FROM tls_certificates WHERE key = $1", key)
	if err != nil {
		if err == sql.ErrNoRows {
			err = autocert.ErrCacheMiss
		} else {
			err = fmt.Errorf("certmanager.Get: error getting cert from db: %w", err)
			logger.Error(err.Error())
		}
		return nil, err
	}

	data, err := certManager.kms.Decrypt(ctx, cert.EncryptedValue, []byte(cert.Key))
	if err != nil {
		err = fmt.Errorf("certmanager.Get: error decrypting value: %w", err)
		logger.Error(err.Error())
		return nil, err
	}

	return data, nil
}

func (certManager *CertManager) Put(ctx context.Context, key string, data []byte) error {
	const query = `INSERT INTO tls_certificates (key, encrypted_value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET encrypted_value = $2`

	logger := slogx.FromCtx(ctx)

	encryptedValue, err := certManager.kms.Encrypt(ctx, data, []byte(key))
	if err != nil {
		err = fmt.Errorf("certmanager.Put: error encrypting cert: %w", err)
		logger.Error(err.Error())
		return err
	}

	_, err = certManager.db.Exec(ctx, query, key, encryptedValue)
	if err != nil {
		err = fmt.Errorf("certmanager.Put: error inserting tls_certificate in DB [%s]: %w", key, err)
		logger.Error(err.Error())
		return err
	}

	return nil
}

func (certManager *CertManager) Delete(ctx context.Context, key string) error {
	logger := slogx.FromCtx(ctx)

	_, err := certManager.db.Exec(ctx, "DELETE FROM tls_certificates WHERE key = $1", key)
	if err != nil {
		err = fmt.Errorf("certmanager.Delete: error deleting tls_certificate: %w", err)
		logger.Error(err.Error())
		return err
	}

	return nil
}
