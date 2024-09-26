package routers

import (
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"go-jwt-template/internal/delivery/middleware"
	"go-jwt-template/pkg/auth"
	cached "go-jwt-template/pkg/database/cached"
	"go-jwt-template/pkg/log"
	"go.opentelemetry.io/otel/trace"
)

func InitRouting(r *gin.Engine, db *sqlx.DB, logger *log.Logs, middlewareStruct middleware.Middleware, jwtUtils auth.JWTUtil, session cached.Session, tracer trace.Tracer) {
	userRouter := r.Group("/user")
	_ = RegisterUserRouter(userRouter, db, session, jwtUtils, logger, tracer, middlewareStruct)
}
