package user

import (
	"context"
	"fmt"
	"github.com/spf13/viper"
	"go-jwt-template/internal/models"
	"go-jwt-template/internal/repository"
	"go-jwt-template/internal/service"
	"go-jwt-template/pkg/auth"
	"go-jwt-template/pkg/cerr"
	"go-jwt-template/pkg/config"
	cached "go-jwt-template/pkg/database/cached"
	"go-jwt-template/pkg/log"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"
	"strconv"
	"time"
)

type ServUser struct {
	UserRepo        repository.UserRepo
	timeoutDuration time.Duration
	session         cached.Session
	jwt             auth.JWTUtil
	log             *log.Logs
}

func InitUserService(
	userRepo repository.UserRepo,
	session cached.Session,
	jwt auth.JWTUtil,
	logger *log.Logs,
) service.UserServ {
	return ServUser{
		UserRepo:        userRepo,
		timeoutDuration: time.Duration(viper.GetInt(config.TimeOut)) * time.Millisecond,
		session:         session,
		jwt:             jwt,
		log:             logger,
	}
}

func (serv ServUser) GetMe(ctx context.Context, userID int, span trace.Span) (*models.User, error) {
	span.AddEvent(service.CallToPostgres)
	return serv.UserRepo.Get(ctx, userID)
}

func (serv ServUser) Create(ctx context.Context, user models.UserCreate) (int, string, string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.PWD), 10)
	if err != nil {
		serv.log.Error(err.Error())
		return 0, "", "", err
	}
	newUser := models.UserCreate{
		UserBase: user.UserBase,
		PWD:      string(hashedPassword),
	}
	id, err := serv.UserRepo.Create(ctx, newUser)
	if err != nil {
		serv.log.Error(err.Error())
		return 0, "", "", err
	}

	userToken := serv.jwt.CreateToken(id)

	userSessionID, err := serv.session.Set(ctx, cached.SessionData{
		UserSession: models.UserSession{
			ID:    id,
			Email: user.Email,
		},
		LoginTimeStamp: time.Now(),
	})

	if err != nil {
		serv.log.Error(err.Error())
		return 0, "", "", err
	}
	serv.log.Info(fmt.Sprintf("create user %v", id))
	return id, userToken, userSessionID, nil
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

func (serv ServUser) Login(ctx context.Context, user models.UserLogin) (int, string, string, error) {
	id, pwd, err := serv.UserRepo.GetPWDbyEmail(ctx, user.Email)
	if err != nil {
		serv.log.Error(err.Error())
		return 0, "", "", err
	}
	err = bcrypt.CompareHashAndPassword([]byte(pwd), []byte(user.PWD))
	if err != nil {
		serv.log.Error(cerr.Err(cerr.InvalidPWD, err).Str())
		return 0, "", "", cerr.Err(cerr.InvalidPWD, err).Error()
	}

	userSessionUUID, err := serv.session.GetUUID(ctx, strconv.Itoa(id))
	if err != nil {
		serv.log.Error(err.Error())
		return 0, "", "", err
	}
	if userSessionUUID != "" {
		userSessionUUID, err = serv.session.UpdateKey(ctx, userSessionUUID, id)
		if err != nil {
			serv.log.Error(err.Error())
			return 0, "", "", err
		}
	} else {
		userSessionUUID, err = serv.session.Set(ctx, cached.SessionData{
			UserSession: models.UserSession{
				ID:    id,
				Email: user.Email,
			},
			LoginTimeStamp: time.Now(),
		})
	}

	jwtToken := serv.jwt.CreateToken(id)

	serv.log.Info(fmt.Sprintf("login user %v", id))
	return id, jwtToken, userSessionUUID, nil
}

func (serv ServUser) ChangePWD(ctx context.Context, user models.UserChangePWD, span trace.Span) (int, error) {
	span.AddEvent(service.CallToPostgres)
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

func (serv ServUser) DeleteMe(ctx context.Context, userID int, sessionID string) error {
	err := serv.session.Delete(ctx, userID, sessionID)
	if err != nil {
		return err
	}
	return serv.UserRepo.Delete(ctx, userID)
}

func (serv ServUser) Refresh(ctx context.Context, sessionID string, span trace.Span) (string, string, error) {
	span.AddEvent(service.CallToRedis)
	userData, err := serv.session.Get(ctx, sessionID)
	if err != nil {
		return "", "", err
	}
	if userData.ID == 0 {
		return "", "", cerr.Err(cerr.UserNotFound, nil).Error()
	}

	span.AddEvent(service.CallToRedis)
	newSessionID, err := serv.session.UpdateKey(ctx, sessionID, userData.ID)
	if err != nil {
		return "", "", err
	}

	span.AddEvent(service.CreateToken)
	userToken := serv.jwt.CreateToken(userData.ID)

	return userToken, newSessionID, nil
}
