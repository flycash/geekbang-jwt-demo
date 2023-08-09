package main

import (
	"github.com/flycash/geekbang-jwt-demo/ratelimit"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	server := gin.Default()
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	server.Use(ratelimit.NewBuilder(redisClient,
		time.Second, 100).Build())
	server.Use(func(ctx *gin.Context) {
		// 不需要登录校验
		if ctx.Request.URL.Path == "/users/login" {
			return
		}
		tokenHeader := ctx.GetHeader("Authorization")
		if tokenHeader == "" {
			// 没登录
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		//segs := strings.SplitN(tokenHeader, " ", 2)
		segs := strings.Split(tokenHeader, " ")
		if len(segs) != 2 {
			// 格式不对，有人瞎搞
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		tokenStr := segs[1]
		claims := &UserClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte("95osj3fUD7fo0mlYdDbncXz4VD2igvf0"), nil
		})
		if err != nil {
			// token 不对，有人搞你
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if token == nil || !token.Valid || claims.Uid == 0 {
			// 按照道理来说，是不可能走到这一步的
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		now := time.Now()
		if claims.ExpiresAt.Time.Before(now) {
			// 过期了
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if claims.UserAgent != ctx.GetHeader("User-Agent") {
			// user agent 不相等
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// 为了演示，假设十秒钟刷新一次
		if claims.ExpiresAt.Time.Sub(now) < time.Second*50 {
			// 刷新
			claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Minute))
			tokenStr, err = token.SignedString([]byte("95osj3fUD7fo0mlYdDbncXz4VD2igvf0"))
			if err != nil {
				// 因为刷新这个事情，并不是一定要做的，所以这里可以考虑打印日志
				// 暂时这样打印
				log.Println(err)
				return
			}
			ctx.Header("x-jwt-token", tokenStr)
			log.Println("刷新了 token")
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
		var claims UserClaims
		claims.Uid = 123
		claims.UserAgent = ctx.GetHeader("User-Agent")
		// 方便演示，我们设置一分钟过期
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Minute))
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenStr, err := token.SignedString([]byte("95osj3fUD7fo0mlYdDbncXz4VD2igvf0"))
		if err != nil {
			// 生成 token 的字符串失败，算是系统错误
			// 你也可以考虑返回 500
			ctx.String(http.StatusOK, "系统错误")
		}
		ctx.Header("x-jwt-token", tokenStr)
		ctx.String(http.StatusOK, "登录成功")
		return
	}
	ctx.String(http.StatusOK, "用户名或者账号错误")
}

type UserClaims struct {
	jwt.RegisteredClaims
	// 假设我们这里要准备在 JWT 里面放一个 Uid
	Uid       int64
	UserAgent string
}
