package example

type User struct {
	ID                string
	Username          string
	Password          string
	FirstName         string
	LastName          string
	Email             string
	EmailVerified     bool
	Phone             string
	PhoneVerified     bool
	PreferredLanguage string
	IsAdmin           bool
}

type UserStorage struct {
	users map[string]*User
}

func (u *UserStorage) CheckUserPassword(username, password string) bool {
	for name, user := range u.users {
		if name == username {
			return user.Password == password
		}
	}
	return false
}

func (u *UserStorage) GetUserByUserId(userId string) *User {
	return u.users[userId]
}

func NewUserStorage() UserStorage {
	return UserStorage{
		users: map[string]*User{
			"id1": {
				ID:                "id1",
				Username:          "test-user1",
				Password:          "verysecure",
				FirstName:         "Test",
				LastName:          "User",
				Email:             "test-user@ihawk.cn",
				EmailVerified:     true,
				Phone:             "11111111111",
				PhoneVerified:     false,
				PreferredLanguage: "German",
				IsAdmin:           true,
			},
			"id2": {
				ID:                "id2",
				Username:          "test-user2",
				Password:          "verysecure",
				FirstName:         "Test",
				LastName:          "User2",
				Email:             "test-user2@ihawk.cn",
				EmailVerified:     true,
				Phone:             "",
				PhoneVerified:     false,
				PreferredLanguage: "German",
				IsAdmin:           false,
			},
		},
	}
}
