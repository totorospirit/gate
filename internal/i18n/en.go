package i18n

func English() *Messages {
	return &Messages{
		Lang:             "en",
		LoginTitle:       "Authentication Required",
		LoginSubtitle:    "Enter your access code to continue",
		CodePlaceholder:  "Access code",
		LoginButton:      "Continue",
		LoginError:       "Invalid access code",
		LoginRateLimited: "Too many attempts. Please wait a moment.",
		LoginLocked:      "Access temporarily locked. Try again later.",
		LoginExpired:     "This access code has expired",
		LoginMaxUses:     "This access code has reached its usage limit",
		LogoutButton:     "Sign out",
		BackToLogin:      "Back to login",
		PoweredBy:        "Protected by",
	}
}
