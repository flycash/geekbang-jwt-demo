package main

import (
	"github.com/flycash/geekbang-jwt-demo/ratelimit"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"net/http"
	"strings"
	"time"
)

func main() {
	server := gin.Default()
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	server.Use(ratelimit.NewBuilder(redisClient, time.Second, 100).Build())
	server.Use(func(ctx *gin.Context) {
		// 登录请求不需要校验
		if ctx.Request.URL.Path == "/users/login" {
			return
		}
		// 我要在这里完成登录校验
		auth := ctx.Request.Header.Get("Authorization")
		if auth == "" {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		segs := strings.Split(auth, " ")
		if len(segs) != 2 {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		tokenStr := segs[1]
		claims := &UserClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte("moyn8y9abnd7q4zkq2m73yw8tu9j5ixm"), nil
		})
		if err != nil {
			// 在这里，生产环境，你要是做的精致。你要监控和告警的
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if claims.UserAgent != ctx.Request.UserAgent() {
			// 有人搞你
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if token == nil || !token.Valid || claims.Uid == 0 {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		now := time.Now()
		// 相当于说，还有 50 秒过期
		if claims.ExpiresAt.Time.Sub(now) < time.Second*50 {
			// 通过校验之后，我要刷新过期时间
			claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Second * 10))
			tokenStr, _ = token.SignedString([]byte("moyn8y9abnd7q4zkq2m73yw8tu9j5ixm"))
			ctx.Header("x-jwt-token", tokenStr)
		}
	})
	server.POST("/users/login", login)
	server.GET("/users/profile", profile)

	// 启动，使用了 8081 端口
	server.Run(":8081")
}

func profile(ctx *gin.Context) {
	ctx.String(http.StatusOK, "这是你的 profile")
}

func login(ctx *gin.Context) {
	type Req struct {
		Email    string
		Password string
	}

	var req Req
	if err := ctx.Bind(&req); err != nil {
		return
	}
	// 正常你应该是从数据库查询的
	// 这里我们直接写死
	if req.Email == "123@qq.com" && req.Password == "123456" {

		// 这就是登录成功了
		// 要做的就是在这里，生成一个 JWT token，返回给前端

		var claims UserClaims
		claims.Uid = 123
		claims.UserAgent = ctx.Request.UserAgent()
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Minute))
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("moyn8y9abnd7q4zkq2m73yw8tu9j5ixm"))
		if err != nil {
			// 你可以用 500
			ctx.String(http.StatusOK, "系统错误")
			return
		}
		ctx.Header("x-jwt-token", tokenString)
		ctx.String(http.StatusOK, "登录成功")
		return
	}
	ctx.String(http.StatusOK, "用户名或者账号错误")
}

// UserClaims 我们要在 JWT token 里面放的数据
type UserClaims struct {
	jwt.RegisteredClaims
	// 用户 ID
	Uid       int64
	UserAgent string
}
