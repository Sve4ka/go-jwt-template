package routers

import (
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"go-template/internal/delivery/middleware"
	"go-template/pkg/log"
)

func InitRouting(r *gin.Engine, db *sqlx.DB, logger *log.Logs, middlewareStruct middleware.Middleware) {
	_ = RegisterUserRouter(r, db, logger)
}
