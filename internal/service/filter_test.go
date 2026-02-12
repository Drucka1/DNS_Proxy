package service

import "testing"

func TestFilter_IsBanned_ExactMatch(t *testing.T) {
	f := NewFilter(map[string]struct{}{
		"banned_namespace1": {},
		"banned_namespace2": {},
	})
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"domaine banni exact", "banned_namespace1", true},
		{"domaine banni exact 2", "banned_namespace2", true},
		{"domaine non banni", "google.com.", false},
		{"chaine vide", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.IsBanned(tt.domain); got != tt.want {
				t.Errorf("IsBanned(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestFilter_IsBanned_SubstringMatch(t *testing.T) {
	f := NewFilter(map[string]struct{}{
		"banned_namespace1": {},
		"banned_namespace2": {},
	})
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"sous-domaine contenant namespace banni", "sub.banned_namespace1.example.com.", true},
		{"prefixe banni", "banned_namespace2.evil.com.", true},
		{"domaine similaire mais pas banni", "not_banned.com.", false},
		{"domaine legitime", "example.org.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.IsBanned(tt.domain); got != tt.want {
				t.Errorf("IsBanned(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}
