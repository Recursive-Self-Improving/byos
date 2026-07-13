//go:build tools

// Package deps pins dependencies selected by the implementation plan until
// their owning packages are implemented.
package deps

import (
	_ "github.com/coreos/go-oidc/v3/oidc"
	_ "github.com/gorilla/csrf"
	_ "github.com/tidwall/gjson"
	_ "github.com/tidwall/sjson"
	_ "github.com/tiktoken-go/tokenizer"
	_ "golang.org/x/oauth2"
	_ "golang.org/x/sync/singleflight"
	_ "gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)
