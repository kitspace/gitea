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
	"code.gitea.io/gitea/modules/timeutil"
	"code.gitea.io/gitea/services/mailer"
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

func KitspaceForgotPassword(ctx *context.Context) {
	if setting.MailService == nil {
		ctx.JSON(http.StatusNotFound, "Password reset isn't activated, contact support.")
		return
	}

	email := ctx.Query("email")

	u, err := models.GetUserByEmail(email)

	if err != nil {
		// TODO: this doesn't make sense!
		if models.IsErrUserNotExist(err) {
			response := make(map[string]string)
			response["ResetPasswdCodeLives"] = timeutil.MinutesToFriendly(
				setting.Service.ResetPwdCodeLives,
				ctx.Locale.Language(),
			)
			response["IsResetSent"] = "true"

			ctx.JSON(http.StatusOK, response)
			return
		}
		ctx.ServerError("user.ResetPasswd(check existence", err)
		return
	}

	if ctx.Cache.IsExist("MailResendLimit_" + u.LowerName) {
		response := make(map[string]bool)
		response["ResendLimited"] = true

		ctx.JSON(http.StatusTooManyRequests, response)
		return
	}

	mailer.SendResetPasswordMail(ctx.Locale, u)

	if err = ctx.Cache.Put("MailResendLimit_", u.LowerName, 100); err != nil {
		log.Error("Set cache(MailResendLimit) fail: %v", err)
	}

	response := make(map[string]string)
	response["ResetPasswdCodeLives"] = timeutil.MinutesToFriendly(
		setting.Service.ResetPwdCodeLives,
		ctx.Locale.Language(),
	)
	response["IsResetSent"] = "true"

	ctx.JSON(http.StatusOK, response)
}

func KitspaceResetPassword(ctx *context.Context) {
	u := handleKitspaceResetPassword(ctx)

	if ctx.Written() {
		return
	}

	if u == nil {
		ctx.JSON(http.StatusOK, "this should be an error.")
		return
	}

	// Validate passwd length.
	passwd := ctx.Query("password")

	if len(passwd) < setting.MinPasswordLength {
		ctx.JSON(http.StatusUnprocessableEntity, "Password is too short.")
		return
	} else if !password.IsComplexEnough(passwd) {
		ctx.JSON(http.StatusUnprocessableEntity, "Password isn't complex enough")
		return
	}

	var err error

	if u.Rands, err = models.GetUserSalt(); err != nil {
		ctx.ServerError("UpdateUser.", err)
		return
	}
	if u.Salt, err = models.GetUserSalt(); err != nil {
		ctx.ServerError("UpdateUser", err)
		return
	}

	u.HashPassword(passwd)
	u.MustChangePassword = false

	if err := models.UpdateUserCols(u, "must_change_password", "passwd", "rands", "salt"); err != nil {
		ctx.ServerError("UpdateUser", err)
		return
	}

	log.Trace("User password reset %s", u.Name)
	ctx.Data["IsResetFailed"] = true

	remember := len(ctx.Query("remember")) != 0

	handleKitspaceSignIn(ctx, u, remember)
}

func handleKitspaceResetPassword(ctx *context.Context) *models.User {
	// Probably the flash error isn't relevant here.

	code := ctx.Query("code")
	ctx.Data["Code"] = code

	if ctx.User != nil {
		ctx.Data["user_signed_in"] = true
	}

	if len(code) == 0 {
		ctx.Flash.Error(ctx.Tr("auth.invalid_code"))
		return nil
	}

	u := models.VerifyUserActiveCode(code)
	if u == nil {
		ctx.Flash.Error(ctx.Tr("auth.invalid_code"))
		return nil
	}

	// Show the user that they are affecting the account that they intended to
	ctx.Data["UserEmail"] = u.Email

	if ctx.User != nil && u.ID != ctx.User.ID {
		ctx.Flash.Error(ctx.Tr("auth.reset_password_wrong_user", ctx.User.Email, u.Email))
		return nil
	}
	return u
}
