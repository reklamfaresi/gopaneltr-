package models

import "gorm.io/gorm"

type Video struct {
	gorm.Model
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url"`
	// Diğer video bilgileri...
}
