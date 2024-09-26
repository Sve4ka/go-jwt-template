package delivery

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"go-jwt-template/docs"
	"go-jwt-template/internal/delivery/middleware"
	"go-jwt-template/internal/delivery/routers"
	"go-jwt-template/pkg/auth"
	cached "go-jwt-template/pkg/database/cached"
	"go-jwt-template/pkg/log"
	"go.opentelemetry.io/otel/trace"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func Start(db *sqlx.DB, log *log.Logs, session cached.Session, tracer trace.Tracer) {
	r := gin.Default()
	r.ForwardedByClientIP = true

	docs.SwaggerInfo.BasePath = "/"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	jwtUtils := auth.InitJWTUtil()
	middlewareStruct := middleware.InitMiddleware(log, jwtUtils, session)
	r.Use(middlewareStruct.CORSMiddleware())

	routers.InitRouting(r, db, log, middlewareStruct, jwtUtils, session, tracer)

	if err := r.Run("0.0.0.0:8080"); err != nil {
		panic(fmt.Sprintf("error running client: %v", err.Error()))
	}
}
