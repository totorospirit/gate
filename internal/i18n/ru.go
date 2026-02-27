package i18n

func Russian() *Messages {
	return &Messages{
		Lang:             "ru",
		LoginTitle:       "Требуется авторизация",
		LoginSubtitle:    "Введите код доступа для продолжения",
		CodePlaceholder:  "Код доступа",
		LoginButton:      "Продолжить",
		LoginError:       "Неверный код доступа",
		LoginRateLimited: "Слишком много попыток. Подождите немного.",
		LoginLocked:      "Доступ временно заблокирован. Попробуйте позже.",
		LoginExpired:     "Срок действия кода доступа истёк",
		LoginMaxUses:     "Код доступа достиг лимита использований",
		LogoutButton:     "Выйти",
		BackToLogin:      "Вернуться к входу",
		PoweredBy:        "Защищено",
	}
}
