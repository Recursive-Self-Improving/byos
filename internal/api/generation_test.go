package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadJSONBodyRequiresAndParsesJSONMediaType(t *testing.T) {
	for _, test := range []struct {
		name, content string
		wantErr       bool
	}{{"missing", "", true}, {"parameterized", "application/json; charset=utf-8", false}, {"wrong", "text/json", true}} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/", strings.NewReader(`{"ok":true}`))
			if test.content != "" {
				request.Header.Set("Content-Type", test.content)
			}
			_, err := ReadJSONBody(httptest.NewRecorder(), request)
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
