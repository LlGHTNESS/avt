package service

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"main.go/internal/domain"

	"database/sql"
	"fmt"

	_ "github.com/lib/pq"

	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/patrickmn/go-cache"
)

var (
	db        *sql.DB
	caching   *cache.Cache
	secretKey = "superSecretKey"
)

func init() {
	var err error
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		"db_service", // хост
		5432,         // порт
		"admin",      // имя пользователя
		"root",       // пароль
		"postgres",   // имя базы данных
	)

	// Инициализация подключения к базе данных
	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatalf("Error opening database: %q", err)
	}

	// Проверка соединения
	err = db.Ping()
	if err != nil {
		log.Fatalf("Error connecting to the database: %q", err)
	}

	// Инициализация кеша
	caching = cache.New(5*time.Minute, 10*time.Minute)
}
func GenerateJWT(userID int, isAdmin bool) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"admin":   isAdmin,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // Токен истекает через 24 часа
	})
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func GetUserBanner(c *gin.Context) {
	// Извлекаем токен и проверяем его валидность
	tokenString := c.GetHeader("Authorization")
	token, err := jwt.Parse(tokenString, SecretKeyFunc)
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Извлекаем флаг use_last_revision
	useLastRevision, _ := strconv.ParseBool(c.DefaultQuery("use_last_revision", "false"))
	admin := isAdmin(c)

	// Определение ID пользователя администратора или обычного пользователя
	var userID interface{}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		userID = claims["user_id"]
	}

	tagID, _ := strconv.Atoi(c.Query("tag_id"))
	featureID, _ := strconv.Atoi(c.Query("feature_id"))

	// Получаем баннер, вызывая специализированную функцию поиска
	banner, err := getBannerFromDBOrCache(useLastRevision, admin, userID, tagID, featureID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "banner not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Возвращаем найденный баннер
	c.JSON(http.StatusOK, banner)
}

// getBannerFromDBOrCache вынесенная функция для получения баннера с логикой кеширования и выбором актуальности данных
func getBannerFromDBOrCache(useLastRevision, isAdmin bool, userID, tagID, featureID interface{}) (domain.Banner, error) {
	// Определяем ключ кеша на основе параметров
	cacheKey := fmt.Sprintf("banner_%v_%v_%v", tagID, featureID, userID)

	// Если флаг useLastRevision не установлен, пытаемся достать баннер из кеша
	if !useLastRevision {
		if cachedBanner, found := caching.Get(cacheKey); found {
			return cachedBanner.(domain.Banner), nil
		}
	}

	var banner domain.Banner
	query := `SELECT banner_id, feature_id, content, is_active, created_at, updated_at
              FROM banners 
              WHERE feature_id = $1 AND banner_id IN 
                  (SELECT banner_id FROM banner_tags WHERE tag_id = $2) 
                  AND (is_active = true OR $3) 
              ORDER BY updated_at DESC 
              LIMIT 1`

	row := db.QueryRow(query, featureID, tagID, isAdmin)
	err := row.Scan(&banner.BannerID, &banner.FeatureID, &banner.Content, &banner.IsActive, &banner.CreatedAt, &banner.UpdatedAt)
	if err != nil {
		return domain.Banner{}, err
	}

	caching.Set(cacheKey, banner, cache.DefaultExpiration)
	return banner, nil
}

// secretKeyFunc функция для передачи ключа в jwt.Parse
func SecretKeyFunc(token *jwt.Token) (interface{}, error) {
	return []byte(secretKey), nil
}

// isAdmin проверяет, является ли пользователь администратором на основе токена
func isAdmin(c *gin.Context) bool {
	tokenString := c.GetHeader("Authorization")
	token, err := jwt.Parse(tokenString, SecretKeyFunc)
	if err != nil || !token.Valid {
		return false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		adminToken := claims["admin"]
		return adminToken == true
	}
	return false
}

func GetBanners(c *gin.Context) {
	// Аутентификация админа
	if !isAdmin(c) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Параметры фильтрации
	featureID, _ := strconv.Atoi(c.DefaultQuery("feature_id", "0"))
	tagID, _ := strconv.Atoi(c.DefaultQuery("tag_id", "0"))

	// Параметры пагинации
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10")) // предполагаем дефолтные значения
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	// Конструируем базовый запрос
	baseQuery := `
        SELECT 
            b.banner_id, b.feature_id, b.content, b.is_active, b.created_at, b.updated_at
        FROM 
            banners b
    `
	whereClauses := []string{}
	params := []interface{}{}

	if featureID > 0 {
		whereClauses = append(whereClauses, "b.feature_id = ?")
		params = append(params, featureID)
	}
	if tagID > 0 {
		baseQuery += `
            JOIN banner_tags bt 
            ON bt.banner_id = b.banner_id
        `
		whereClauses = append(whereClauses, "bt.tag_id = ?")
		params = append(params, tagID)
	}
	if len(whereClauses) > 0 {
		baseQuery += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	finalQuery := fmt.Sprintf("%s LIMIT ? OFFSET ?", baseQuery)
	params = append(params, limit, offset)

	rows, err := db.Query(finalQuery, params...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch banners"})
		return
	}
	defer rows.Close()

	var banners []domain.Banner
	for rows.Next() {
		var banner domain.Banner
		if err := rows.Scan(&banner.BannerID, &banner.FeatureID, &banner.Content, &banner.IsActive, &banner.CreatedAt, &banner.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read banner data"})
			return
		}
		banners = append(banners, banner)
	}

	if err = rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed during banner data retrieval"})
		return
	}

	c.JSON(http.StatusOK, banners)
}
func CreateBanner(c *gin.Context) {
	var newBanner domain.Banner
	if err := c.BindJSON(&newBanner); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot begin transaction"})
		return
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		"INSERT INTO banners (feature_id, content, is_active) VALUES (?, ?, ?)",
		newBanner.FeatureID,
		newBanner.Content,
		newBanner.IsActive,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create banner"})
		return
	}

	bannerID, err := result.LastInsertId()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve last insert ID"})
		return
	}
	newBanner.BannerID = int(bannerID)

	// Вставка связей баннера с тегами
	for _, tagID := range newBanner.TagIDs {
		_, err := tx.Exec(
			"INSERT INTO banner_tags (banner_id, tag_id) VALUES (?, ?)",
			newBanner.BannerID,
			tagID,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create banner-tag link"})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "transaction commit failed"})
		return
	}

	// Сброс кеша, связанного с этим баннером, как мера предосторожности
	cacheKey := fmt.Sprintf("banner_%v", newBanner.BannerID)
	caching.Delete(cacheKey)

	c.JSON(http.StatusCreated, newBanner)
}

func UpdateBanner(c *gin.Context) {
	bannerID := c.Param("id")

	var updateBanner domain.Banner
	if err := c.BindJSON(&updateBanner); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	_, err := db.Exec(
		"UPDATE banners SET feature_id = ?, content = ?, is_active = ? WHERE banner_id = ?",
		updateBanner.FeatureID,
		updateBanner.Content,
		updateBanner.IsActive,
		bannerID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update banner"})
		return
	}

	cacheKey := fmt.Sprintf("banner_%v", bannerID)
	caching.Delete(cacheKey)

	c.JSON(http.StatusOK, gin.H{"message": "banner updated successfully"})
}

func DeleteBanner(c *gin.Context) {
	bannerID := c.Param("id")

	_, err := db.Exec("DELETE FROM banners WHERE banner_id = ?", bannerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete banner"})
		return
	}

	cacheKey := fmt.Sprintf("banner_%v", bannerID)
	caching.Delete(cacheKey)

	c.JSON(http.StatusOK, gin.H{"message": "banner deleted successfully"})
}

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func AuthenticateUser(username, password string) (int, bool, error) {
	// Здесь должна быть реализация проверки учетных данных
	if username == "exampleUser" && password == "examplePassword" {
		return 1, true, nil
	}
	return 0, false, fmt.Errorf("invalid username or password")
}
