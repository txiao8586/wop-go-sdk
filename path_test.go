package wop

import "testing"

func TestValidateAPIPath(t *testing.T) {
	cases := []struct {
		path    string
		wantErr bool
	}{
		{"/gateway/order/create", false},
		{"gateway/order/create", true},
		{"//attacker.example/path", true},
		{"/gateway/order?x=1", true},
		{"/gateway/order#frag", true},
		{"http://evil/path", true},
		{"", true},
	}
	for _, tc := range cases {
		err := validateAPIPath(tc.path)
		if tc.wantErr && err == nil {
			t.Errorf("path=%q 应失败", tc.path)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("path=%q 不应失败: %v", tc.path, err)
		}
	}
}

func TestJoinServerRootAndPath(t *testing.T) {
	got := joinServerRootAndPath("https://gw.example.com/gateway", "/gateway/order/create")
	want := "https://gw.example.com/gateway/gateway/order/create"
	if got != want {
		t.Fatalf("got=%q want=%q", got, want)
	}
	got = joinServerRootAndPath("https://gw.example.com/gateway/", "/gateway/order/create")
	if got != want {
		t.Fatalf("trailing slash: got=%q", got)
	}
}
