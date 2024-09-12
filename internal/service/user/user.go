package user

import (
	"context"
	"fmt"
	"go-template/internal/models"
	"go-template/internal/repository"
	"go-template/internal/service"
	"go-template/pkg/cerr"
	"go-template/pkg/log"
	"golang.org/x/crypto/bcrypt"
)

type ServUser struct {
	UserRepo repository.UserRepo
	log      *log.Logs
}

func InitUserService(userRepo repository.UserRepo, log *log.Logs) service.UserServ {
	return &ServUser{UserRepo: userRepo, log: log}
}

func (serv ServUser) Create(ctx context.Context, user models.UserCreate) (int, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.PWD), 10)
	if err != nil {
		serv.log.Error(err.Error())
		return 0, err
	}
	newUser := models.UserCreate{
		UserBase: user.UserBase,
		PWD:      string(hashedPassword),
	}
	id, err := serv.UserRepo.Create(ctx, newUser)
	if err != nil {
		serv.log.Error(err.Error())
		return 0, err
	}
	serv.log.Info(fmt.Sprintf("create user %v", id))
	return id, nil
}

func (serv ServUser) Get(ctx context.Context, id int) (*models.User, error) {
	user, err := serv.UserRepo.Get(ctx, id)
	if err != nil {
		serv.log.Error(err.Error())
		return nil, err
	}
	serv.log.Info(fmt.Sprintf("get user %v", id))
	return user, nil
}

func (serv ServUser) Login(ctx context.Context, user models.UserLogin) (int, error) {
	id, pwd, err := serv.UserRepo.GetPWDbyEmail(ctx, user.Email)
	if err != nil {
		serv.log.Error(err.Error())
		return 0, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(pwd), []byte(user.PWD))
	if err != nil {
		serv.log.Error(cerr.Err(cerr.InvalidPWD, err).Str())
		return 0, cerr.Err(cerr.InvalidPWD, err).Error()
	}
	serv.log.Info(fmt.Sprintf("login user %v", id))
	return id, nil
}

func (serv ServUser) ChangePWD(ctx context.Context, user models.UserChangePWD) (int, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(user.NewPWD), 10)
	if err != nil {
		serv.log.Error(cerr.Err(cerr.Hash, err).Str())
		return 0, cerr.Err(cerr.Hash, err).Error()
	}
	newPWD := models.UserChangePWD{
		ID:     user.ID,
		NewPWD: string(hash),
	}
	id, err := serv.UserRepo.ChangePWD(ctx, newPWD)
	if err != nil {
		serv.log.Error(err.Error())
		return 0, err
	}
	serv.log.Info(fmt.Sprintf("change pwd user %v", id))
	return id, nil
}

func (serv ServUser) Delete(ctx context.Context, id int) error {
	err := serv.UserRepo.Delete(ctx, id)
	if err != nil {
		serv.log.Error(err.Error())
		return err
	}
	serv.log.Info(fmt.Sprintf("delete user %v", id))
	return nil
}
