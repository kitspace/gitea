package user

import (
	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/auth"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/password"
	"code.gitea.io/gitea/modules/setting"
	"net/http"

	"code.gitea.io/gitea/modules/context"
)

func KitspaceSignUp(ctx *context.Context, form auth.RegisterForm) {
	// TODO: docs.
	if len(form.Password) < setting.MinPasswordLength {
		ctx.JSON(http.StatusUnprocessableEntity, "Password is too short.")
		return
	}

	// TODO: update complexity settings.
	if !password.IsComplexEnough(form.Password) {
		ctx.JSON(http.StatusUnprocessableEntity, "Password isn't complex enough")
		return
	}

	u := &models.User{
		Name:     form.UserName,
		Email:    form.Email,
		Passwd:   form.Password,
		IsActive: !setting.Service.RegisterEmailConfirm,
	}

	if err := models.CreateUser(u); err != nil {
		switch {
		case models.IsErrUserAlreadyExist(err):
			ctx.JSON(http.StatusConflict, "User already exists.")
		case models.IsErrEmailAlreadyUsed(err):
			ctx.JSON(http.StatusConflict, "Email is already used.")
		case models.IsErrNameReserved(err):
			ctx.JSON(http.StatusConflict, "Name is reserved.")
		case models.IsErrNamePatternNotAllowed(err):
			ctx.JSON(http.StatusUnprocessableEntity, "This name pattern isn't allowed.")
		default:
			ctx.ServerError("Signup", err)
		}
		return
	} else {
		// TODO: once email configuration is setup, the whole else block is no longer needed.
		log.Trace("Account created: %s", u.Name)
		response := make(map[string]bool)
		response["IsRegisteredSuccessfully"] = true

		ctx.JSON(http.StatusOK, response)
		return
	}

	// Send confirmation email
	// TODO: this needs updating the conf file in /custom
	//if setting.Service.RegisterEmailConfirm && u.ID > 1 {
	//	mailer.SendActivateAccountMail(ctx.Locale, u)
	//
	//	response := make(map[string]string)
	//	response["IsRegisterMailSent"] = "true"
	//	response["email"] = u.Email
	//	response["ActiveCodeLives"] = timeutil.MinutesToFriendly(setting.Service.ActiveCodeLives,
	//		ctx.Locale.Language())
	//
	//	if err := ctx.Cache.Put("MailResendLimit_"+u.LowerName, u.LowerName, 180); err != nil {
	//		log.Error("Set cache(MailResendLimit) fail: %v", err)
	//	}
	//
	//	ctx.JSON(http.StatusOK, response)
	//	return
	//}
}
