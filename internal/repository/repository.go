package repository

import (
	"context"
	"go-jwt-template/internal/models"
)

type UserRepo interface {
	Create(ctx context.Context, user models.UserCreate) (int, error)
	Get(ctx context.Context, id int) (*models.User, error)
	GetPWDbyEmail(ctx context.Context, user string) (int, string, error)
	ChangePWD(ctx context.Context, user models.UserChangePWD) (int, error)
	Delete(ctx context.Context, id int) error
}
