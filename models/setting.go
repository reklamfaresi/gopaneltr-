package models

import "gorm.io/gorm"

type Setting struct {
	gorm.Model
	Key   string `json:"key"`
	Value string `json:"value"`
	// Diğer ayar bilgileri...
}
