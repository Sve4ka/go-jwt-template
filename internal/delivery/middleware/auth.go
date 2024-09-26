package middleware

import (
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/spf13/viper"
	"go-jwt-template/pkg/config"
	"net/http"
	"strings"
	"time"
)

const (
	CUserID    = "userID"
	CSessionID = "Session"
)

func (m Middleware) Authorization() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()

		auth := c.GetHeader("Authorization")
		if !strings.Contains(auth, "Bearer") {
			m.logger.Info(fmt.Sprintf("unathorized (NO JWT) access at: %v", c.Request.URL.Path))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "no bearer provided in authorization"})
			return
		}

		// WITH Bearer <token>
		jwtToken := strings.Split(auth, " ")[1]

		id, err := m.jwtUtil.Authorize(jwtToken)
		if errors.Is(err, jwt.ErrTokenExpired) {
			m.logger.Info(fmt.Sprintf("token expired at: %v", c.Request.URL.Path))
			c.AbortWithStatusJSON(http.StatusUpgradeRequired, gin.H{"detail": "JWT expired"})
			return
		}
		if err != nil {
			m.logger.Error(fmt.Sprintf("token parse error at: %v", c.Request.URL.Path))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "error on parsing JWT"})
			return
		}

		c.Set(CUserID, id)

		sessionID := c.GetHeader("Session")
		if sessionID == "" {
			m.logger.Info(fmt.Sprintf("unathorized (NO SESSIONID) access at: %v", c.Request.URL.Path))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "no sessionID provided in Session"})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), time.Millisecond*time.Duration(viper.GetInt(config.TimeOut)))

		defer cancel()

		userData, err := m.session.Get(ctx, sessionID)
		if err != nil {
			m.logger.Error(fmt.Sprintf("error on getting sessionData from redis at: %v", c.Request.URL.Path))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"detail": "error on getting sessionData from redis"})
			return
		}

		if userData.ID == 0 {
			m.logger.Error(fmt.Sprintf("there is no userData on given sessionID: %v", c.Request.URL.Path))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "no userData by given SessionID"})
			return
		}

		c.Set(CSessionID, sessionID)

		// BEFORE AND...

		c.Next()

		// ...AFTER THE REQUEST

		latency := time.Since(t)
		status := c.Writer.Status()

		m.logger.Info(fmt.Sprintf("handled %v, latency: %v, response status: %v", c.Request.URL.Path, latency, status))
	}
}
