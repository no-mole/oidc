package oidc

type UserInfo struct {
	Subject string `json:"sub"`
	UserInfoProfile
	UserInfoEmail
	UserInfoPhone
	Address *UserInfoAddress `json:"address"`

	Claims map[string]any `json:"-"`
}

type UserInfoProfile struct {
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	MiddleName        string `json:"middle_name"`
	Nickname          string `json:"nickname"`
	Profile           string `json:"profile"`
	Picture           string `json:"picture"`
	Website           string `json:"website"`
	Gender            string `json:"gender"`
	Birthdate         string `json:"birthdate"`
	Zoneinfo          string `json:"zoneinfo"`
	Locale            string `json:"locale"`
	UpdatedAt         int64  `json:"updated_at"`
	PreferredUsername string `json:"preferred_username"`
}

type UserInfoEmail struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

type UserInfoPhone struct {
	PhoneNumber         string `json:"phone_number"`
	PhoneNumberVerified bool   `json:"phone_number_verified"`
}

type UserInfoAddress struct {
	Formatted     string `json:"formatted"`
	StreetAddress string `json:"street_address"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postal_code"`
	Country       string `json:"country"`
}

type UserStorage interface {
	GetPassword(username string) string
}
