package models

import "gorm.io/gorm"

type Image struct {
	gorm.Model
	Title       string `json:"title"`
	Description string `json:"description"`
	Path        string `json:"path"` // Resim dosya yolu
	// Diğer resim bilgileri...
}
