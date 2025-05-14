package config

type EmailsProvider string

const (
	EmailsProviderConsole EmailsProvider = "console"
	EmailsProviderSes     EmailsProvider = "ses"
)

type S3Provider string

const (
	S3ProviderScaleway S3Provider = "scaleway"
	S3ProviderAws      S3Provider = "aws"
)

const (
	protocolHttp  = "http"
	protocolHttps = "https"
)

const (
	envMarkdownNinjaConfig = "MARKDOWN_NINJA_CONFIG"
	envDatabaseUrl         = "DATABASE_URL"
	envPort                = "PORT"
	envAwsAccessKeyID      = "AWS_ACCESS_KEY_ID"
	envAwsSecretAccessKey  = "AWS_SECRET_ACCESS_KEY"
	envAwsDefaultRegion    = "AWS_DEFAULT_REGION"
)

const (
	// DefaultConfigPath is the default (relative) location of the configuration file
	DefaultConfigPath = "markdown_ninja_server.yml"

	defaultHttpPort       uint16 = 8080
	defaultHttpAccessLogs bool   = false

	// small postgres databases are generally capped at 100 connections so we need to keep around
	// 15 for administrative access and zero-downtime deployments
	defaultDatabasePoolSize int    = 85
	postgresUrlScheme       string = "postgres"
)

const (
	stripePublicKeyPrefix     = "pk_"
	stripeSecretKeyPrefix     = "sk_"
	stripePrefixPrice         = "price_"
	stripeWebhookSecretPrefix = "whsec_"
)

const (
	JWT_KEY_MIN_SIZE = 40
)
