// Copyright (c) 2019 The Jaeger Authors.
// SPDX-License-Identifier: Apache-2.0

package tlscfg

import (
	"flag"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configtls"

	"github.com/jaegertracing/jaeger/pkg/config"
)

func TestClientFlags(t *testing.T) {
	cmdLine := []string{
		"--prefix.tls.ca=ca-file",
		"--prefix.tls.cert=cert-file",
		"--prefix.tls.key=key-file",
		"--prefix.tls.server-name=HAL1",
		"--prefix.tls.skip-host-verify=true",
	}

	tests := []struct {
		option string
	}{
		{
			option: "--prefix.tls.enabled=true",
		},
	}

	for _, test := range tests {
		t.Run(test.option, func(t *testing.T) {
			v := viper.New()
			command := cobra.Command{}
			flagSet := &flag.FlagSet{}
			flagCfg := ClientFlagsConfig{
				Prefix: "prefix",
			}
			flagCfg.AddFlags(flagSet)
			command.PersistentFlags().AddGoFlagSet(flagSet)
			v.BindPFlags(command.PersistentFlags())

			err := command.ParseFlags(append(cmdLine, test.option))
			require.NoError(t, err)
			tlsOpts, err := flagCfg.InitFromViper(v)
			require.NoError(t, err)
			assert.Equal(t, Options{
				Enabled:        true,
				CAPath:         "ca-file",
				CertPath:       "cert-file",
				KeyPath:        "key-file",
				ServerName:     "HAL1",
				SkipHostVerify: true,
			}, tlsOpts)
		})
	}
}

func TestServerFlags(t *testing.T) {
	cmdLine := []string{
		"##placeholder##", // replaced in each test below
		"--prefix.tls.enabled=true",
		"--prefix.tls.cert=cert-file",
		"--prefix.tls.key=key-file",
		"--prefix.tls.cipher-suites=TLS_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"--prefix.tls.min-version=1.2",
		"--prefix.tls.max-version=1.3",
	}

	tests := []struct {
		option string
		file   string
	}{
		{
			option: "--prefix.tls.client-ca=client-ca-file",
			file:   "client-ca-file",
		},
	}

	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			v := viper.New()
			command := cobra.Command{}
			flagSet := &flag.FlagSet{}
			flagCfg := ServerFlagsConfig{
				Prefix: "prefix",
			}
			flagCfg.AddFlags(flagSet)
			command.PersistentFlags().AddGoFlagSet(flagSet)
			v.BindPFlags(command.PersistentFlags())

			cmdLine[0] = test.option
			err := command.ParseFlags(cmdLine)
			require.NoError(t, err)
			tlsOpts, err := flagCfg.InitFromViper(v)
			require.NoError(t, err)
			assert.Equal(t, Options{
				Enabled:      true,
				CertPath:     "cert-file",
				KeyPath:      "key-file",
				ClientCAPath: test.file,
				CipherSuites: []string{"TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
				MinVersion:   "1.2",
				MaxVersion:   "1.3",
			}, tlsOpts)
		})
	}
}

func TestServerCertReloadInterval(t *testing.T) {
	tests := []struct {
		config ServerFlagsConfig
	}{
		{
			config: ServerFlagsConfig{
				Prefix:                   "enabled",
				EnableCertReloadInterval: true,
			},
		},
		{
			config: ServerFlagsConfig{
				Prefix:                   "disabled",
				EnableCertReloadInterval: false,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.config.Prefix, func(t *testing.T) {
			_, command := config.Viperize(test.config.AddFlags)
			err := command.ParseFlags([]string{
				"--" + test.config.Prefix + ".tls.enabled=true",
				"--" + test.config.Prefix + ".tls.reload-interval=24h",
			})
			if !test.config.EnableCertReloadInterval {
				assert.ErrorContains(t, err, "unknown flag")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestFailedTLSFlags verifies that TLS options cannot be used when tls.enabled=false
func TestFailedTLSFlags(t *testing.T) {
	clientTests := []string{
		".ca=blah",
		".cert=blah",
		".key=blah",
		".server-name=blah",
		".skip-host-verify=true",
	}
	serverTests := []string{
		".cert=blah",
		".key=blah",
		".client-ca=blah",
		".cipher-suites=blah",
		".min-version=1.1",
		".max-version=1.3",
	}
	allTests := []struct {
		side  string
		tests []string
	}{
		{side: "client", tests: clientTests},
		{side: "server", tests: serverTests},
	}

	for _, metaTest := range allTests {
		t.Run(metaTest.side, func(t *testing.T) {
			for _, test := range metaTest.tests {
				t.Run(test, func(t *testing.T) {
					type UnderTestClient interface {
						AddFlags(flags *flag.FlagSet)
						InitFromViper(v *viper.Viper) (configtls.ClientConfig, error)
					}
					type UnderTestServer interface {
						AddFlags(flags *flag.FlagSet)
						InitFromViper(v *viper.Viper) (*configtls.ServerConfig, error)
					}
					var underTestClient UnderTestClient
					var underTestServer UnderTestServer
					if metaTest.side == "client" {
						underTestClient = &ClientFlagsConfig{
							Prefix: "prefix",
						}
					} else {
						underTestServer = &ServerFlagsConfig{
							Prefix: "prefix",
						}
					}
					var v *viper.Viper
					var command *cobra.Command
					if metaTest.side == "client" {
						v, command = config.Viperize(underTestClient.AddFlags)
					} else {
						v, command = config.Viperize(underTestServer.AddFlags)
					}

					cmdLine := []string{
						"--prefix.tls.enabled=true",
						"--prefix.tls" + test,
					}
					err := command.ParseFlags(cmdLine)
					require.NoError(t, err)
					if metaTest.side == "client" {
						_, err = underTestClient.InitFromViper(v)
					} else {
						_, err = underTestServer.InitFromViper(v)
					}
					require.NoError(t, err)

					cmdLine[0] = "--prefix.tls.enabled=false"
					err = command.ParseFlags(cmdLine)
					require.NoError(t, err)
					if metaTest.side == "client" {
						_, err = underTestClient.InitFromViper(v)
					} else {
						_, err = underTestServer.InitFromViper(v)
					}
					require.Error(t, err)
					require.EqualError(t, err, "prefix.tls.* options cannot be used when prefix.tls.enabled is false")
				})
			}
		})
	}
}
