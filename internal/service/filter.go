package service

import "strings"

// Gère le filtrage des domaines interdits.
type Filter struct {
	banned map[string]struct{}
}

// Crée un filtre de domaines.
func NewFilter(banned map[string]struct{}) *Filter {
	return &Filter{banned: banned}
}

// Vérifie si le domaine est interdit (match exact ou sous-chaîne).
func (f *Filter) IsBanned(name string) bool {
	if _, ok := f.banned[name]; ok {
		return true
	}
	for b := range f.banned {
		if strings.Contains(name, b) {
			return true
		}
	}
	return false
}
