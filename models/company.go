package models

import "gorm.io/gorm"

type Company struct {
	gorm.Model
	AboutUs string `json:"about_us"`
	Mission string `json:"mission"`
	Vision  string `json:"vision"`
	Address string `json:"address"`
	Phone   string `json:"phone"`
	Email   string `json:"email"`
	// Diğer şirket bilgileri...
}
