package delivery

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"go-template/docs"
	"go-template/internal/delivery/middleware"
	"go-template/internal/delivery/routers"
	"go-template/pkg/log"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func Start(db *sqlx.DB, log *log.Logs) {
	r := gin.Default()
	r.ForwardedByClientIP = true
	//r.SetTrustedProxies([]string{"127.0.0.1"})
	docs.SwaggerInfo.BasePath = "/"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	middlewareStruct := middleware.InitMiddleware(log)
	r.Use(middlewareStruct.CORSMiddleware())

	routers.InitRouting(r, db, log, middlewareStruct)

	if err := r.Run("0.0.0.0:8080"); err != nil {
		panic(fmt.Sprintf("error running client: %v", err.Error()))
	}
}
