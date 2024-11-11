package models

import "gorm.io/gorm"

type Service struct {
	gorm.Model
	Title       string `json:"title"`
	Description string `json:"description"`
	Image       string `json:"image"` // Resim URL'si veya dosya yolu
	// Diğer hizmet bilgileri...
}
