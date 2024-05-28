package users

type Role int

const (
	// RoleNone is the role for users with no permissions, or the default role.
	RoleNone Role = -1

	// RoleAdmin is the role for administrators.
	RoleAdmin Role = iota

	// RoleReviewBow is the role for users who can review bag-of-words.
	RoleReviewBow

	// RoleReviewInteresting is the role for users who can review interesting data.
	RoleReviewInteresting

	// RoleSearchSimilar is the role for users who can search for similar data.
	RoleSearchSimilar
)

func (r Role) String() string {
	switch r {
	case RoleNone:
		return "none"
	case RoleAdmin:
		return "admin"
	case RoleReviewBow:
		return "review_bow"
	case RoleReviewInteresting:
		return "review_interesting"
	case RoleSearchSimilar:
		return "search_similar"
	default:
		return "unknown"
	}
}

// ConvertToRole converts an integer to a Role.
func ConvertToRole(role int) Role {
	switch role {
	case 0:
		return RoleAdmin
	case 1:
		return RoleReviewBow
	case 2:
		return RoleReviewInteresting
	case 3:
		return RoleSearchSimilar
	default:
		return RoleNone
	}
}
