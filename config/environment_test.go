package config

import "testing"

func TestParseEnvironment(t *testing.T) {
	const invalid = "AIPAY_ENVIRONMENT must be development, test or production"
	const removed = "AIPAY_ENVIRONMENT no longer accepts staging (A130): use development for the Kubernetes staging cluster, or production"
	for _, tc := range []struct {
		value   string
		want    Environment
		wantErr string
	}{
		{"", Production, ""},
		{"development", Development, ""},
		{"test", Test, ""},
		{"production", Production, ""},
		{"staging", "", removed},
		{"Development", "", invalid},
		{" development", "", invalid},
		{"development ", "", invalid},
		{"development\n", "", invalid},
		{"test\x00", "", invalid},
		{"dev", "", invalid},
		{"prod", "", invalid},
		{"testing", "", invalid},
	} {
		got, err := ParseEnvironment(tc.value)
		if tc.wantErr == "" {
			if got != tc.want || err != nil {
				t.Errorf("ParseEnvironment(%q) = (%q, %v), want (%q, nil)", tc.value, got, err, tc.want)
			}
		} else if err == nil || err.Error() != tc.wantErr {
			t.Errorf("ParseEnvironment(%q) error = %v, want %q", tc.value, err, tc.wantErr)
		}
	}
}

func TestLoadEnvironment(t *testing.T) {
	if _, err := LoadEnvironment(nil); err == nil {
		t.Fatal("LoadEnvironment accepted a nil reader")
	}
	calls := 0
	got, err := LoadEnvironment(func(key string) string {
		calls++
		if key != "AIPAY_ENVIRONMENT" {
			t.Errorf("unexpected environment key %q", key)
		}
		return "test"
	})
	if calls != 1 || got != Test || err != nil {
		t.Fatalf("LoadEnvironment = (%q, %v) after %d reads, want (test, nil) after one read", got, err, calls)
	}
}

func TestEnvironmentPredicates(t *testing.T) {
	for _, tc := range []struct {
		env               Environment
		development       bool
		developmentOrTest bool
	}{
		{Development, true, true},
		{Test, false, true},
		{Production, false, false},
		{"", false, false},
		{Staging, false, false},
		{Environment("unknown"), false, false},
	} {
		if got := tc.env.IsDevelopment(); got != tc.development {
			t.Errorf("IsDevelopment(%q) = %t, want %t", tc.env, got, tc.development)
		}
		if got := tc.env.IsDevelopmentOrTest(); got != tc.developmentOrTest {
			t.Errorf("IsDevelopmentOrTest(%q) = %t, want %t", tc.env, got, tc.developmentOrTest)
		}
	}
}
