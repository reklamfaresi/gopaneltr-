package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/reklamfaresi/gopaneltr-/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"net/http"
	"os"
	"strconv"
)

var db *gorm.DB // db'yi global olarak tanımla

func main() {
	// ... (Veritabanı bağlantısı ve tablolar oluşturma) ...

	// Gin router'ı oluştur
	router := gin.Default()

	// Endpointler
	router.POST("/register", registerHandler)
	router.POST("/login", loginHandler)
	router.PUT("/users/:id", authMiddleware, updateUserHandler)

	// ... (Diğer endpointler) ...

	// 404 handler'ı
	router.NoRoute(noRouteHandler)

	// API'yi 8080 portunda başlat
	router.Run(":8080")
}

func noRouteHandler(context *gin.Context) {

}

// registerHandler fonksiyonu
func registerHandler(c *gin.Context) {
	// İstekten kullanıcı bilgilerini al
	var input struct {
		Name     string `json:"name" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Parola hash'leme
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Parola hash'lenirken hata oluştu"})
		return
	}

	// Kullanıcıyı veritabanına kaydet
	user := models.User{Name: input.Name, Email: input.Email, Password: string(hashedPassword), Role: "editor"} // Varsayılan rolü "editor" olarak ayarlayın
	result := db.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Kullanıcı kaydedilirken hata oluştu"})
		return
	}

	// Başarı mesajı döndür
	c.JSON(http.StatusCreated, gin.H{"message": "Kullanıcı başarıyla kaydedildi"})
}

// generateToken fonksiyonu
func generateToken(user models.User) (string, error) {
	// JWT oluştur
	jwtSecret := os.Getenv("JWT_SECRET") // Ortam değişkeninden gizli anahtarı oku
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    user.ID,
		"email": user.Email,
		"role":  user.Role, // Kullanıcının rolünü JWT'ye ekle
	})

	// JWT'yi imzala ve string olarak döndür
	return token.SignedString([]byte(jwtSecret))
}

// loginHandler fonksiyonu
func loginHandler(c *gin.Context) {
	// İstekten kullanıcı bilgilerini al
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Kullanıcıyı veritabanında bul
	var user models.User
	result := db.Where("email = ?", input.Email).First(&user)
	if result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz email veya parola"})
		return
	}

	// Parolayı doğrula
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz email veya parola"})
		return
	}

	// JWT oluştur
	tokenString, err := generateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT oluşturulurken hata oluştu"})
		return
	}

	// JWT'yi döndür
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// authMiddleware fonksiyonu
func authMiddleware(c *gin.Context) {
	// İstekten Authorization header'ını al
	tokenString := c.GetHeader("Authorization")

	// "Bearer " ön ekini kaldır
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	// JWT'yi ayrıştır
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// İmzalama algoritmasını kontrol et
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("beklenmeyen imzalama yöntemi: %v", token.Header["alg"])
		}

		// Gizli anahtarı döndür
		jwtSecret := os.Getenv("JWT_SECRET")
		return []byte(jwtSecret), nil
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz token"})
		return
	}

	// JWT'nin geçerliliğini kontrol et
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Kullanıcı ID'sini context'e ekle
		c.Set("userId", claims["id"])
		c.Next()
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz token"})
	}
}

// updateUserHandler fonksiyonu
func updateUserHandler(c *gin.Context) {
	// URL'den kullanıcı ID'sini al
	userId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz kullanıcı ID'si"})
		return
	}

	// JWT'den kullanıcı ID'sini al
	// (authMiddleware tarafından eklendi)
	claims, ok := c.Get("userId")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Yetkisiz erişim"})
		return
	}

	// claims["id"]'nin tipini int olarak dönüştür
	claimsId := uint(claims.(float64))

	// Kullanıcının kendi hesabını veya admin yetkisiyle başka bir hesabı güncellemesine izin ver
	if claimsId != uint(userId) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Başka bir kullanıcının bilgilerini güncelleyemezsiniz"})
		return
	}

	// İstekten güncellenecek bilgileri al
	var input struct {
		Name  string `json:"name"`
		Email string `json:"email" binding:"email"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Kullanıcıyı veritabanında bul
	var user models.User
	result := db.First(&user, userId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Kullanıcı bulunamadı"})
		return
	}

	// Bilgileri güncelle
	if input.Name != "" {
		user.Name = input.Name
	}
	if input.Email != "" {
		user.Email = input.Email
	}
	db.Save(&user)

	// Başarı mesajı döndür
	c.JSON(http.StatusOK, gin.H{"message": "Bilgiler başarıyla güncellendi"})
}
