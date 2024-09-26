package routers

import (
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"go-jwt-template/internal/delivery/handlers"
	"go-jwt-template/internal/delivery/middleware"
	"go-jwt-template/internal/repository/user"
	userserv "go-jwt-template/internal/service/user"
	"go-jwt-template/pkg/auth"
	cached "go-jwt-template/pkg/database/cached"
	"go-jwt-template/pkg/log"
	"go.opentelemetry.io/otel/trace"
)

func RegisterUserRouter(userRouter *gin.RouterGroup, db *sqlx.DB, session cached.Session, jwt auth.JWTUtil, logger *log.Logs, tracer trace.Tracer, middlewareStruct middleware.Middleware) *gin.RouterGroup {
	userRepo := user.InitUserRepository(db)
	userService := userserv.InitUserService(userRepo, session, jwt, logger)
	userHandler := handlers.InitUserHandler(userService, session, tracer)

	userRouter.POST("/create", userHandler.Create)
	userRouter.POST("/login", userHandler.Login)
	userRouter.POST("/refresh", userHandler.Refresh)
	userRouter.Use(middlewareStruct.Authorization())
	userRouter.GET("/:id", userHandler.Get)
	userRouter.PUT("/change/pwd", userHandler.ChangePWD)
	userRouter.DELETE("/delete/:id", userHandler.Delete)
	userRouter.GET("/me", userHandler.GetMe)
	userRouter.DELETE("/delete", userHandler.DeleteMe)
	return userRouter
}
