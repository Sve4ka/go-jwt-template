package service

import (
	"context"
	"go-jwt-template/internal/models"
	"go.opentelemetry.io/otel/trace"
)

type UserServ interface {
	Create(ctx context.Context, user models.UserCreate) (int, string, string, error)
	Get(ctx context.Context, id int) (*models.User, error)
	Login(ctx context.Context, user models.UserLogin) (int, string, string, error)
	ChangePWD(ctx context.Context, user models.UserChangePWD, span trace.Span) (int, error)
	Delete(ctx context.Context, id int) error
	GetMe(ctx context.Context, userID int, span trace.Span) (*models.User, error)
	DeleteMe(ctx context.Context, userID int, sessionID string) error
	Refresh(ctx context.Context, sessionID string, span trace.Span) (string, string, error)
}
