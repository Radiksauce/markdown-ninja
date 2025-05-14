package repository

type ContactsRepository struct{}

func NewContactsRepository() ContactsRepository {
	return ContactsRepository{}
}
