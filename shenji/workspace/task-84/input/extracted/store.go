package main

type Document struct {
	ID      string
	OwnerID string
	Body    string
}

type Store struct {
	documents map[string]Document
}

func NewStore() *Store {
	return &Store{documents: map[string]Document{
		"1": {ID: "1", OwnerID: "alice", Body: "alice payroll"},
		"2": {ID: "2", OwnerID: "bob", Body: "bob roadmap"},
	}}
}

func (s *Store) GetDocument(id string) (Document, bool) {
	doc, ok := s.documents[id]
	return doc, ok
}
