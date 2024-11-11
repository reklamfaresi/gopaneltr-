package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/reklamfaresi/gopaneltr-/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"net/http"
	"strconv"
)

var db *gorm.DB // db'yi global olarak tanımla

func main() {
	// Veritabanı bağlantı bilgileri
	dsn := "root:@tcp(127.0.0.1:3306)/gopaneltr?charset=utf8mb4&parseTime=True&loc=Local"
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Veritabanına bağlanılamadı!")
	}

	// Veritabanında tablo oluştur
	db.AutoMigrate(
		&models.User{},
		&models.Company{},
		&models.Service{},
		&models.Video{},
		&models.Image{},
		&models.FAQ{},
		&models.Post{},
		&models.Setting{},
	)
	db.AutoMigrate(&models.User{})

	// Gin router'ı oluştur
	router := gin.Default()

	// Endpointler
	router.POST("/register", registerHandler)
	router.POST("/login", loginHandler)
	router.PUT("/users/:id", authMiddleware, updateUserHandler) // authMiddleware eklendi
	router.POST("/companies", createCompanyHandler)
	router.GET("/companies", getCompaniesHandler)
	router.GET("/companies/:id", getCompanyHandler)
	router.PUT("/companies/:id", updateCompanyHandler)
	router.DELETE("/companies/:id", deleteCompanyHandler)
	// Service endpointleri
	router.POST("/services", createServiceHandler)
	router.GET("/services", getServicesHandler)
	router.GET("/services/:id", getServiceHandler)
	router.PUT("/services/:id", updateServiceHandler)
	router.DELETE("/services/:id", deleteServiceHandler)
	router = gin.Default()
	router.NoRoute(noRouteHandler)
	// Video endpointleri
	router.POST("/videos", createVideoHandler)
	router.GET("/videos", getVideosHandler)
	router.GET("/videos/:id", getVideoHandler)
	router.PUT("/videos/:id", updateVideoHandler)
	router.DELETE("/videos/:id", deleteVideoHandler)
	// Image endpointleri
	router.POST("/images", createImageHandler)
	router.GET("/images", getImagesHandler)
	router.GET("/images/:id", getImageHandler)
	router.PUT("/images/:id", updateImageHandler)
	router.DELETE("/images/:id", deleteImageHandler)
	// FAQ endpointleri
	router.POST("/faqs", createFAQHandler)
	router.GET("/faqs", getFAQsHandler)
	router.GET("/faqs/:id", getFAQHandler)
	router.PUT("/faqs/:id", updateFAQHandler)
	router.DELETE("/faqs/:id", deleteFAQHandler)
	// API'yi 8080 portunda başlat
	router.Run(":8080")
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
	user := models.User{Name: input.Name, Email: input.Email, Password: string(hashedPassword)}
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
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    user.ID,
		"email": user.Email,
	})

	// JWT'yi imzala ve string olarak döndür
	return token.SignedString([]byte("gizli_anahtar"))
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
		return []byte("gizli_anahtar"), nil
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

}
func createCompanyHandler(c *gin.Context) {
	// İstekten şirket bilgilerini al
	var input models.Company
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Şirketi veritabanına kaydet
	result := db.Create(&input)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Şirket kaydedilirken hata oluştu"})
		return
	}

	// Başarı mesajı döndür
	c.JSON(http.StatusCreated, gin.H{"message": "Şirket başarıyla kaydedildi"})
}
func getCompaniesHandler(c *gin.Context) {
	var companies []models.Company
	result := db.Find(&companies)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Şirketler getirilirken hata oluştu"})
		return
	}

	c.JSON(http.StatusOK, companies)
}
func getCompanyHandler(c *gin.Context) {
	companyId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz şirket ID'si"})
		return
	}

	var company models.Company
	result := db.First(&company, companyId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Şirket bulunamadı"})
		return
	}

	c.JSON(http.StatusOK, company)
}
func updateCompanyHandler(c *gin.Context) {
	companyId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz şirket ID'si"})
		return
	}

	// İstekten güncellenecek bilgileri al
	var input models.Company
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Şirketi veritabanında bul
	var company models.Company
	result := db.First(&company, companyId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Şirket bulunamadı"})
		return
	}

	// Bilgileri güncelle
	db.Model(&company).Updates(input)

	// Başarı mesajı döndür
	c.JSON(http.StatusOK, gin.H{"message": "Şirket bilgileri başarıyla güncellendi"})
}
func deleteCompanyHandler(c *gin.Context) {
	companyId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz şirket ID'si"})
		return
	}

	// Şirketi veritabanında bul
	var company models.Company
	result := db.First(&company, companyId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Şirket bulunamadı"})
		return
	}

	// Şirketi sil
	db.Delete(&company)

	// Başarı mesajı döndür
	c.JSON(http.StatusOK, gin.H{"message": "Şirket başarıyla silindi"})
}
func createServiceHandler(c *gin.Context) {
	// İstekten hizmet bilgilerini al
	var input models.Service
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hizmeti veritabanına kaydet
	result := db.Create(&input)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Hizmet kaydedilirken hata oluştu"})
		return
	}

	// Başarı mesajı döndür
	c.JSON(http.StatusCreated, gin.H{"message": "Hizmet başarıyla kaydedildi"})
}
func getServicesHandler(c *gin.Context) {
	var services []models.Service
	result := db.Find(&services)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Hizmetler getirilirken hata oluştu"})
		return
	}

	c.JSON(http.StatusOK, services)
}
func getServiceHandler(c *gin.Context) {
	serviceId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz hizmet ID'si"})
		return
	}

	var service models.Service
	result := db.First(&service, serviceId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hizmet bulunamadı"})
		return
	}

	c.JSON(http.StatusOK, service)
}
func updateServiceHandler(c *gin.Context) {
	serviceId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz hizmet ID'si"})
		return
	}

	// İstekten güncellenecek bilgileri al
	var input models.Service
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hizmeti veritabanında bul
	var service models.Service
	result := db.First(&service, serviceId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hizmet bulunamadı"})
		return
	}

	// Bilgileri güncelle
	db.Model(&service).Updates(input)

	// Başarı mesajı döndür
	c.JSON(http.StatusOK, gin.H{"message": "Hizmet bilgileri başarıyla güncellendi"})
}
func deleteServiceHandler(c *gin.Context) {
	serviceId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz hizmet ID'si"})
		return
	}

	// Hizmeti veritabanında bul
	var service models.Service
	result := db.First(&service, serviceId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hizmet bulunamadı"})
		return
	}

	// Hizmeti sil
	db.Delete(&service)

	// Başarı mesajı döndür
	c.JSON(http.StatusOK, gin.H{"message": "Hizmet başarıyla silindi"})
}
func noRouteHandler(c *gin.Context) {
	c.HTML(http.StatusNotFound, "404.html", gin.H{
		"title":   "Sayfa Bulunamadı",
		"message": "Aradığınız sayfa bulunamadı.",
	})
}
func createVideoHandler(c *gin.Context) {
	// İstekten video bilgilerini al
	var input models.Video
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Videoyu veritabanına kaydet
	result := db.Create(&input)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Video kaydedilirken hata oluştu"})
		return
	}

	// Başarı mesajı döndür
	c.JSON(http.StatusCreated, gin.H{"message": "Video başarıyla kaydedildi"})
}
func getVideosHandler(c *gin.Context) {
	var videos []models.Video
	result := db.Find(&videos)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Videolar getirilirken hata oluştu"})
		return
	}

	c.JSON(http.StatusOK, videos)
}
func getVideoHandler(c *gin.Context) {
	videoId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz video ID'si"})
		return
	}

	var video models.Video
	result := db.First(&video, videoId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Video bulunamadı"})
		return
	}

	c.JSON(http.StatusOK, video)
}
func updateVideoHandler(c *gin.Context) {
	videoId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz video ID'si"})
		return
	}

	// İstekten güncellenecek bilgileri al
	var input models.Video
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Videoyu veritabanında bul
	var video models.Video
	result := db.First(&video, videoId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Video bulunamadı"})
		return
	}

	// Bilgileri güncelle
	db.Model(&video).Updates(input)

	// Başarı mesajı döndür
	c.JSON(http.StatusOK, gin.H{"message": "Video bilgileri başarıyla güncellendi"})
}
func deleteVideoHandler(c *gin.Context) {
	videoId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz video ID'si"})
		return
	}

	// Videoyu veritabanında bul
	var video models.Video
	result := db.First(&video, videoId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Video bulunamadı"})
		return
	}

	// Videoyu sil
	db.Delete(&video)

	// Başarı mesajı döndür
	c.JSON(http.StatusOK, gin.H{"message": "Video başarıyla silindi"})
}
func createImageHandler(c *gin.Context) {
	// İstekten resim bilgilerini al
	var input models.Image
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Resmi veritabanına kaydet
	result := db.Create(&input)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Resim kaydedilirken hata oluştu"})
		return
	}

	// Başarı mesajı döndür
	c.JSON(http.StatusCreated, gin.H{"message": "Resim başarıyla kaydedildi"})
}
func getImagesHandler(c *gin.Context) {
	var images []models.Image
	result := db.Find(&images)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Resimler getirilirken hata oluştu"})
		return
	}

	c.JSON(http.StatusOK, images)
}
func getImageHandler(c *gin.Context) {
	imageId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz resim ID'si"})
		return
	}

	var image models.Image
	result := db.First(&image, imageId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Resim bulunamadı"})
		return
	}

	c.JSON(http.StatusOK, image)
}
func updateImageHandler(c *gin.Context) {
	imageId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz resim ID'si"})
		return
	}

	// İstekten güncellenecek bilgileri al
	var input models.Image
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Resmi veritabanında bul
	var image models.Image
	result := db.First(&image, imageId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Resim bulunamadı"})
		return
	}

	// Bilgileri güncelle
	db.Model(&image).Updates(input)

	// Başarı mesajı döndür
	c.JSON(http.StatusOK, gin.H{"message": "Resim bilgileri başarıyla güncellendi"})
}
func deleteImageHandler(c *gin.Context) {
	imageId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz resim ID'si"})
		return
	}

	// Resmi veritabanında bul
	var image models.Image
	result := db.First(&image, imageId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Resim bulunamadı"})
		return
	}

	// Resmi sil
	db.Delete(&image)

	// Başarı mesajı döndür
	c.JSON(http.StatusOK, gin.H{"message": "Resim başarıyla silindi"})
}
func createFAQHandler(c *gin.Context) {
	// İstekten FAQ bilgilerini al
	var input models.FAQ
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// FAQ'yu veritabanına kaydet
	result := db.Create(&input)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "FAQ kaydedilirken hata oluştu"})
		return
	}

	// Başarı mesajı döndür
	c.JSON(http.StatusCreated, gin.H{"message": "FAQ başarıyla kaydedildi"})
}
func getFAQsHandler(c *gin.Context) {
	var faqs []models.FAQ
	result := db.Find(&faqs)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "FAQ'lar getirilirken hata oluştu"})
		return
	}

	c.JSON(http.StatusOK, faqs)
}
func getFAQHandler(c *gin.Context) {
	faqId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz FAQ ID'si"})
		return
	}

	var faq models.FAQ
	result := db.First(&faq, faqId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "FAQ bulunamadı"})
		return
	}

	c.JSON(http.StatusOK, faq)
}
func updateFAQHandler(c *gin.Context) {
	faqId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz FAQ ID'si"})
		return
	}

	// İstekten güncellenecek bilgileri al
	var input models.FAQ
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// FAQ'yu veritabanında bul
	var faq models.FAQ
	result := db.First(&faq, faqId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "FAQ bulunamadı"})
		return
	}

	// Bilgileri güncelle
	db.Model(&faq).Updates(input)

	// Başarı mesajı döndür
	c.JSON(http.StatusOK, gin.H{"message": "FAQ bilgileri başarıyla güncellendi"})
}
func deleteFAQHandler(c *gin.Context) {
	faqId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz FAQ ID'si"})
		return
	}

	// FAQ'yu veritabanında bul
	var faq models.FAQ
	result := db.First(&faq, faqId)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "FAQ bulunamadı"})
		return
	}

	// FAQ'yu sil
	db.Delete(&faq)

	// Başarı mesajı döndür
	c.JSON(http.StatusOK, gin.H{"message": "FAQ başarıyla silindi"})
}
