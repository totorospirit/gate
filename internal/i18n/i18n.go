package i18n

import "strings"

type Messages struct {
	Lang              string
	LoginTitle        string
	LoginSubtitle     string
	CodePlaceholder   string
	LoginButton       string
	LoginError        string
	LoginRateLimited  string
	LoginLocked       string
	LoginExpired      string
	LoginMaxUses      string
	LogoutButton      string
	BackToLogin       string
	PoweredBy         string
}

var languages = map[string]*Messages{
	"en": English(),
	"ru": Russian(),
	"ja": Japanese(),
}

func Get(acceptLanguage string) *Messages {
	for _, lang := range parseAcceptLanguage(acceptLanguage) {
		if m, ok := languages[lang]; ok {
			return m
		}
		// Try base language (e.g., "en-US" -> "en")
		if base, _, ok := strings.Cut(lang, "-"); ok {
			if m, ok := languages[base]; ok {
				return m
			}
		}
	}
	return languages["en"]
}

func parseAcceptLanguage(header string) []string {
	var langs []string
	for _, part := range strings.Split(header, ",") {
		lang := strings.TrimSpace(part)
		if idx := strings.Index(lang, ";"); idx != -1 {
			lang = lang[:idx]
		}
		lang = strings.TrimSpace(lang)
		if lang != "" {
			langs = append(langs, strings.ToLower(lang))
		}
	}
	return langs
}
