package main

import (
	"github.com/reklamfaresi/gopaneltr-/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {
	// Veritabanı bağlantı bilgileri
	dsn := "root:@tcp(127.0.0.1:3306)/gopaneltr?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Veritabanına bağlanılamadı!")
	}

	// Veritabanında tablo oluştur
	db.AutoMigrate(&models.User{})

}
