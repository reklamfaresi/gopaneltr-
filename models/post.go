package models

import "gorm.io/gorm"

type Post struct {
	gorm.Model
	Title   string `json:"title"`
	Content string `json:"content"`
	Author  string `json:"author"`
	// Diğer blog yazısı bilgileri...
}
