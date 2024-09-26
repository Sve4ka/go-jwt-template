package handlers

import (
	"context"
	"errors"
	"go-jwt-template/internal/delivery/middleware"
	"go-jwt-template/internal/models"
	"go-jwt-template/internal/service"
	"go-jwt-template/pkg/cerr"
	"go-jwt-template/pkg/database/cached"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization

// @title localhost
// @version 1.0
// @description lupa
// @host localhost:8080
// @BasePath /

type UserHandler struct {
	service service.UserServ
	session cached.Session
	tracer  trace.Tracer
}

func InitUserHandler(service service.UserServ, session cached.Session, tracer trace.Tracer) UserHandler {
	return UserHandler{
		service: service,
		session: session,
		tracer:  tracer,
	}
}

// @Summary Create user
// @Tags user
// @Accept  json
// @Produce  json
// @Param data body models.UserCreate true "user create"
// @Success 200 {object} int "Successfully created user"
// @Failure 400 {object} map[string]string "Invalid input"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/create [post]
func (handler UserHandler) Create(g *gin.Context) {
	var newUser models.UserCreate

	if err := g.ShouldBindJSON(&newUser); err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	id, userToken, sessionID, err := handler.service.Create(ctx, newUser)
	if err != nil {
		g.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	g.JSON(http.StatusOK, gin.H{"id": id, "jwt": userToken, "session": sessionID})
}

// @Summary GetMe user data
// @Tags user
// @Accept  json
// @Produce  json
// @Param Session header string true "Session ID"
// @Param Authorization header string true "Insert your access token" default(Bearer <Add access token here>)
// @Success 200 {object} []models.User "Successfully response with user data"
// @Failure 400 {object} map[string]string "JWT is absent or invalid input"
// @Failure 403 {object} map[string]string "JWT is invalid or expired"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/me [get]
// @Security Bearer
func (handler UserHandler) GetMe(g *gin.Context) {
	ctx, span := handler.tracer.Start(g.Request.Context(), GetMe)
	defer span.End()

	span.AddEvent(EventGetUserID)
	userID := g.GetInt(middleware.CUserID)

	span.SetAttributes(attribute.Int(middleware.CUserID, userID))

	token := g.GetHeader("Authorization")
	if token == "" {
		g.JSON(http.StatusUnauthorized, gin.H{"detail": "No token provided"})
		return
	}

	span.AddEvent(CallToService)
	user, err := handler.service.GetMe(ctx, userID, span)
	if err != nil {
		span.RecordError(err, trace.WithAttributes(
			attribute.String("SomeErrorInfo", "FATAL!!!!")),
		)
		span.SetStatus(codes.Error, err.Error())
		g.JSON(http.StatusInternalServerError, gin.H{"detail": err})
		return
	}

	g.JSON(http.StatusOK, user)
}

// @Summary Get user
// @Tags user
// @Accept  json
// @Produce  json
// @Param id query int true "UserID"
// @Param Authorization header string true "Bearer <ваш_токен>"
// @Success 200 {object} int "Successfully get user"
// @Failure 400 {object} map[string]string "Invalid input"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/{id} [get]
// @Security Bearer
func (handler UserHandler) Get(c *gin.Context) {
	id := c.Query("id")
	aid, err := strconv.Atoi(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	user, err := handler.service.Get(ctx, aid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

// @Summary Change password
// @Tags user
// @Accept  json
// @Produce  json
// @Param Authorization header string true "Bearer <ваш_токен>"
// @Param data body models.UserChangePWD true "change password"
// @Success 200 {object} int "Success changing"
// @Failure 400 {object} map[string]string "Invalid id"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/change/pwd [put]
// @Security Bearer
func (handler UserHandler) ChangePWD(g *gin.Context) {
	ctx, span := handler.tracer.Start(g.Request.Context(), GetMe)
	defer span.End()
	var user models.UserChangePWD
	if err := g.ShouldBindJSON(&user); err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	id, err := handler.service.ChangePWD(ctx, user, span)
	if err != nil {
		g.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	g.JSON(http.StatusOK, gin.H{"change": "success", "id": id})
}

// @Summary Login user
// @Tags user
// @Accept  json
// @Produce  json
// @Param data body models.UserLogin true "user login"
// @Success 200 {object} int "Successfully login user"
// @Failure 400 {object} map[string]string "Invalid input"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/login [post]
func (handler UserHandler) Login(g *gin.Context) {
	var user models.UserLogin

	if err := g.ShouldBindJSON(&user); err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := g.Request.Context()

	userToken, sessionID, id, err := handler.service.Login(ctx, user)
	if err != nil {
		g.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	g.JSON(http.StatusOK, gin.H{"userID": id, "JWT": userToken, "Session": sessionID})
}

// @Summary Delete user
// @Tags user
// @Accept  json
// @Produce  json
// @Param id query int true "UserID"
// @Success 200 {object} int "Successfully deleted"
// @Failure 400 {object} map[string]string "Invalid id"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/delete/{id} [delete]
// @Security Bearer
func (handler UserHandler) Delete(g *gin.Context) {
	userID := g.Query("id")
	id, err := strconv.Atoi(userID)
	if err != nil {
		g.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = handler.service.Delete(ctx, id)
	if err != nil {
		g.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	g.JSON(http.StatusOK, gin.H{"delete": id})
}

// @Summary DeleteMe user
// @Tags user
// @Accept  json
// @Produce  json
// @Param Session header string true "Session ID"
// @Param Authorization header string true "Insert your access token" default(Bearer <Add access token here>)
// @Success 200 {object} map[string]string "Successfully response"
// @Failure 400 {object} map[string]string "JWT is absent or invalid input"
// @Failure 403 {object} map[string]string "JWT is invalid or expired"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/delete [delete]
// @Security Bearer
func (handler UserHandler) DeleteMe(c *gin.Context) {
	ctx := c.Request.Context()

	sessionID := c.GetString(middleware.CSessionID)
	userID := c.GetInt(middleware.CUserID)

	err := handler.service.DeleteMe(ctx, userID, sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err})
		return
	}

	c.JSON(http.StatusOK, gin.H{"detail": "successfully!"})
}

// @Summary Refresh tokens
// @Tags user
// @Accept  json
// @Produce  json
// @Param Session header string true "Session ID"
// @Success 200 {object} map[string]string "Successfully authorized, returning JWT and new session_id"
// @Failure 400 {object} map[string]string "Invalid input"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /user/refresh [put]
// @Security Bearer
func (handler UserHandler) Refresh(c *gin.Context) {
	ctx, span := handler.tracer.Start(c.Request.Context(), Refresh)
	defer span.End()

	sessionID := c.GetHeader(middleware.CSessionID)

	span.AddEvent(CallToService)
	userToken, newSessionID, err := handler.service.Refresh(ctx, sessionID, span)
	if err != nil {
		if errors.Is(err, cerr.Err(cerr.UserNotFound, err).Error()) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": err.Error()})
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, err)
		span.RecordError(err, trace.WithAttributes(
			attribute.String(middleware.CSessionID, sessionID)))
		return
	}

	c.JSON(http.StatusOK, gin.H{"JWT": userToken, "Session": newSessionID})
}
