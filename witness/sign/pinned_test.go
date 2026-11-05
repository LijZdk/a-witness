package sign

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPinnedJWKSExactMatch(t *testing.T) {
	body, pub := jwksBody(t, "seal-2026")
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write(body)
	}))
	defer srv.Close()
	pinnedURL := srv.URL + "/jwks.json"
	p, err := NewPinnedJWKS(&JWKSFetcher{Client: srv.Client()}, pinnedURL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	for _, id := range []string{
		srv.URL + "/jwks.jso#seal-2026",      // a prefix of the pinned URL
		srv.URL + "/jwks.json/x#seal-2026",   // a longer path
		srv.URL + "/jwks.json?x=1#seal-2026", // a query
		pinnedURL + "x#seal-2026",            // a longer name
		"https://evil.example/jwks.json#seal-2026",
		"https://127.0.0.1@evil.example/jwks.json#seal-2026",
		"https://evil.example@" + srv.URL[len("https://"):] + "/jwks.json#seal-2026", // host@evil
		"https://" + "x" + srv.URL[len("https://"):] + "/jwks.json#seal-2026",        // host suffix trick
		pinnedURL, // no kid
		"",
	} {
		if _, err := p.PublicKey(ctx, id); !errors.Is(err, ErrUnknownKey) {
			t.Errorf("%q: got %v, want ErrUnknownKey", id, err)
		}
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d requests were made for addresses that are not pinned", n)
	}

	got, err := p.PublicKey(ctx, pinnedURL+"#seal-2026")
	if err != nil || !pub.Equal(got) {
		t.Fatalf("the pinned address did not resolve: %v", err)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("%d requests for the pinned address, want 1", n)
	}
	var nilPinned *PinnedJWKS
	if _, err := nilPinned.PublicKey(ctx, pinnedURL+"#seal-2026"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("a nil *PinnedJWKS resolved: %v", err)
	}
}

func TestNewPinnedJWKSRejectsBadURLs(t *testing.T) {
	f := &JWKSFetcher{}
	if _, err := NewPinnedJWKS(nil, "https://a.example/jwks.json"); err == nil {
		t.Error("accepted a nil fetcher")
	}
	if _, err := NewPinnedJWKS(f); err == nil {
		t.Error("accepted no URLs")
	}
	for _, s := range []string{
		"http://a.example/jwks.json",
		"//a.example/jwks.json",
		"a.example/jwks.json",
		"https:///jwks.json",
		"https://",
		"https://user@a.example/jwks.json",
		"https://user:pw@a.example/jwks.json",
		"https://a.example/jwks.json?x=1",
		"https://a.example/jwks.json?",
		"https://a.example/jwks.json#kid",
		"https://a.example/jwks.json#",
		"https://a.example/a/../jwks.json",
		"https://a.example/./jwks.json",
		"https://a.example/a/..",
		"https:a.example/jwks.json",
		"https://a.example/ jwks.json",
		"",
	} {
		if _, err := NewPinnedJWKS(f, s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if _, err := NewPinnedJWKS(f, "https://a.example/jwks.json", "https://b.example/.well-known/jwks.json"); err != nil {
		t.Errorf("refused good URLs: %v", err)
	}
	if _, err := NewPinnedJWKS(f, "https://a.example/jwks.json", "http://b.example/x"); err == nil {
		t.Error("accepted a list with one bad URL")
	}
}
