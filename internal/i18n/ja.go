package i18n

func Japanese() *Messages {
	return &Messages{
		Lang:             "ja",
		LoginTitle:       "認証が必要です",
		LoginSubtitle:    "続行するにはアクセスコードを入力してください",
		CodePlaceholder:  "アクセスコード",
		LoginButton:      "続行",
		LoginError:       "無効なアクセスコードです",
		LoginRateLimited: "試行回数が多すぎます。しばらくお待ちください。",
		LoginLocked:      "アクセスが一時的にロックされています。後でもう一度お試しください。",
		LoginExpired:     "このアクセスコードは期限切れです",
		LoginMaxUses:     "このアクセスコードは使用回数の上限に達しました",
		LogoutButton:     "サインアウト",
		BackToLogin:      "ログインに戻る",
		PoweredBy:        "認証：",
	}
}
