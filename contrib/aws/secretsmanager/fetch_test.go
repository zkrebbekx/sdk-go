package secretsmanager

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"go.temporal.io/sdk/contrib/envconfig"
)

func TestLambdaExtensionFetcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/secretsmanager/get" || r.Header.Get(lambdaExtensionTokenHdr) != "session-token" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Query().Get("secretId") {
		case "arn:aws:secretsmanager:us-east-1:123:secret:string":
			_ = json.NewEncoder(w).Encode(map[string]any{"SecretString": "string-value", "VersionId": "ver1"})
		case "binary":
			_ = json.NewEncoder(w).Encode(map[string]any{"SecretBinary": []byte("binary-value")})
		case "empty":
			_ = json.NewEncoder(w).Encode(map[string]any{"VersionId": "ver1"})
		case "bad-json":
			_, _ = w.Write([]byte("{"))
		case "server-error":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal error"))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("bad request"))
		}
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	t.Setenv(envLambdaExtensionPort, u.Port())
	t.Setenv(envAWSSessionToken, "session-token")

	f := newLambdaExtensionFetcher(u.Port())
	require.Equal(t, fetchPathExtension, f.path())
	v, err := f.fetch(context.Background(), "arn:aws:secretsmanager:us-east-1:123:secret:string")
	require.NoError(t, err)
	require.Equal(t, secretValue{value: []byte("string-value"), versionID: "ver1"}, v)
	v, err = f.fetch(context.Background(), "binary")
	require.NoError(t, err)
	require.Equal(t, secretValue{value: []byte("binary-value")}, v)
	_, err = f.fetch(context.Background(), "missing")
	require.ErrorContains(t, err, "returned status 400: bad request")
	require.Equal(t, failureClientError, classifyFailure(err))
	_, err = f.fetch(context.Background(), "server-error")
	require.ErrorContains(t, err, "returned status 500: internal error")
	require.Equal(t, failureServerError, classifyFailure(err))
	_, err = f.fetch(context.Background(), "empty")
	require.ErrorContains(t, err, "secret has no value")
	require.Equal(t, failureInvalidResponse, classifyFailure(err))
	_, err = f.fetch(context.Background(), "bad-json")
	require.ErrorContains(t, err, "failed decoding")
	require.Equal(t, failureInvalidResponse, classifyFailure(err))

	// Extension is used when no client is given and the port env var is set
	// (configure triggers an eager load, which exercises the fetcher)
	opts, err := envconfig.LoadClientOptions(envconfig.LoadClientOptionsRequest{
		DisableFile: true,
		EnvLookup:   mapEnv{envAPIKeyID: "arn:aws:secretsmanager:us-east-1:123:secret:string"},
		Extensions:  []envconfig.ClientConfigExtension{Extension{}},
	})
	require.NoError(t, err)
	metrics := newRecordingMetrics()
	opts.MetricsHandler = metrics
	require.NoError(t, configure(t, &opts))
	require.NotNil(t, opts.Credentials)
	require.Equal(t, int64(1), metrics.counter(metricCacheLookup,
		labelSecretType, secretTypeAPIKey, labelFetchPath, fetchPathExtension, labelResult, lookupMiss))
}

func TestSDKFetcher(t *testing.T) {
	f := &sdkFetcher{client: newFakeClient(map[string]string{"id": "value"})}
	require.Equal(t, fetchPathSDK, f.path())
	v, err := f.fetch(context.Background(), "id")
	require.NoError(t, err)
	require.Equal(t, secretValue{value: []byte("value"), versionID: fakeVersionID("value")}, v)
}
