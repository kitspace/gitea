// TODO: docs, encode all response as jsom.
package user

import (
	"fmt"
	"net/http"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/auth"
	"code.gitea.io/gitea/modules/base"
	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/password"
	"code.gitea.io/gitea/modules/setting"
)

func KitspaceSignUp(ctx *context.Context, form auth.RegisterForm) {
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

func KitspaceSignIn(ctx *context.Context, form auth.SignInForm) {
	u, err := models.UserSignIn(form.UserName, form.Password)

	if err != nil {
		switch {
		case models.IsErrUserNotExist(err):
			ctx.JSON(http.StatusNotFound, "Wrong username or password.")
			log.Info("Failed authentication attempt for %s from %s", form.UserName, ctx.RemoteAddr())
		case models.IsErrEmailAlreadyUsed(err):
			ctx.JSON(http.StatusConflict, "This email has already been used.")
			log.Info("Failed authentication attempt for %s from %s", form.UserName, ctx.RemoteAddr())
		case models.IsErrUserProhibitLogin(err):
			ctx.JSON(http.StatusForbidden, "Prohibited login")
			log.Info("Failed authentication attempt for %s from %s", form.UserName, ctx.RemoteAddr())
		case models.IsErrUserInactive(err):
			if setting.Service.RegisterEmailConfirm {
				ctx.JSON(http.StatusOK, "Activate your account.")
			} else {
				ctx.JSON(http.StatusForbidden, "Prohibited login")
				log.Info("Failed authentication attempt for %s from %s", form.UserName, ctx.RemoteAddr())
			}
		default:
			ctx.ServerError("KitspaceSignIn", err)
		}
		return
	}
	handleKitspaceSignIn(ctx, u, form.Remember)
}

func handleKitspaceSignIn(ctx *context.Context, user *models.User, remember bool) {
	// This needs re-write.
	if remember {
		days := 86400 * setting.LogInRememberDays
		ctx.SetCookie(
			setting.CookieUserName,
			user.Name,
			days,
			setting.AppSubURL,
			setting.SessionConfig.Domain,
			setting.SessionConfig.Secure,
			true)
		ctx.SetSuperSecureCookie(
			base.EncodeMD5(user.Rands+user.Passwd),
			setting.CookieRememberName,
			user.Name,
			days,
			setting.AppSubURL,
			setting.SessionConfig.Domain,
			setting.SessionConfig.Secure,
			true)
	}

	if err := ctx.Session.Set("uid", user.ID); err != nil {
		log.Error("Error setting uid %s session: %v", user.Name, err)
	}

	if err := ctx.Session.Set("uname", user.Name); err != nil {
		log.Error("Error setting uname")
	}

	if err := ctx.Session.Release(); err != nil {
		log.Error("Unable to store session: %v", err)
	}

	// Language setting of the user overwrites the one previously set
	// If the user does not have a locale set, we save the current one.
	if len(user.Language) == 0 {
		user.Language = ctx.Locale.Language()

		if err := models.UpdateUserCols(user, "language"); err != nil {
			log.Error(fmt.Sprintf("Error updating user language [user: %d, locale: %s]", user.ID, user.Language))

			// TODO: replace this a proper redirect json response
			ctx.JSON(http.StatusPermanentRedirect, "")
			return
		}
	}

	ctx.SetCookie(
		"lang",
		user.Language,
		nil,
		setting.AppSubURL,
		setting.SessionConfig.Domain,
		setting.SessionConfig.Secure,
		true)

	// Clear whatever CSRF has right now, force to generate a new one
	ctx.SetCookie(
		setting.CSRFCookieName,
		"",
		-1,
		setting.AppSubURL,
		setting.SessionConfig.Domain,
		setting.SessionConfig.Secure,
		true)

	// Register last login
	user.SetLastLogin()

	if err := models.UpdateUserCols(user, "last_login_unix"); err != nil {
		ctx.ServerError("UpdateUserCols", err)
		ctx.JSON(http.StatusPermanentRedirect, "")
		return
	}
	ctx.JSON(http.StatusPermanentRedirect, "")
	return
}
