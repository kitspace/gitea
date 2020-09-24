package user

import (
	"net/http"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/auth"
	"code.gitea.io/gitea/modules/context"
	"code.gitea.io/gitea/modules/eventsource"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/password"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/timeutil"
	"code.gitea.io/gitea/services/mailer"
)

// KitspaceSignUp custom sign-up compatible with Kitspace architecture
func KitspaceSignUp(ctx *context.Context, form auth.RegisterForm) {
	// swagger:operation POST /user/kitspace/sign_up
	// ---
	// summary: Create a user
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/RegisterForm"
	// responses:
	//   "201":
	//     "$ref": "#/responses/User"
	//   "400":
	//     "$ref": "#/responses/error"
	//	 "409":
	//     "$ref": "#/response/error
	//   "422":
	//     "$ref": "#/responses/validationError"
	response := make(map[string]string)

	if len(form.Password) < setting.MinPasswordLength {
		response["error"] = "UnprocessableEntity"
		response["message"] = "Password is too short."

		ctx.JSON(http.StatusUnprocessableEntity, response)
		return
	}

	if !password.IsComplexEnough(form.Password) {
		response["error"] = "UnprocessableEntity"
		response["message"] = "Password isn't complex enough."

		ctx.JSON(http.StatusUnprocessableEntity, response)
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
			response["error"] = "Conflict"
			response["message"] = "User already exists."

			ctx.JSON(http.StatusConflict, response)
		case models.IsErrEmailAlreadyUsed(err):
			response["error"] = "Conflict"
			response["message"] = "Email is already used."

			ctx.JSON(http.StatusConflict, response)
		case models.IsErrNameReserved(err):
			response["error"] = "Conflict"
			response["message"] = "Name is reserved."

			ctx.JSON(http.StatusConflict, response)
		case models.IsErrNamePatternNotAllowed(err):
			response["error"] = "UnprocessableEntity"
			response["message"] = "This name pattern isn't allowed."

			ctx.JSON(http.StatusUnprocessableEntity, response)
		default:
			ctx.ServerError("Signup", err)
		}
		return
	} else {
		log.Trace("Account created: %s", u.Name)
	}

	// Send confirmation email
	if setting.Service.RegisterEmailConfirm && u.ID > 1 {
		mailer.SendActivateAccountMail(ctx.Locale, u)

		response := make(map[string]string)
		response["email"] = u.Email
		response["ActiveCodeLives"] = timeutil.MinutesToFriendly(
			setting.Service.ActiveCodeLives,
			ctx.Locale.Language(),
		)

		if err := ctx.Cache.Put("MailResendLimit_"+u.LowerName, u.LowerName, 180); err != nil {
			log.Error("Set cache(MailResendLimit) fail: %v", err)
		}

		ctx.JSON(http.StatusOK, response)
	} else {
		// make the mock response similar to the response when mailing works
		response := map[string]string{
			"email":           u.Email,
			"ActiveCodeLives": timeutil.MinutesToFriendly(setting.Service.ActiveCodeLives, ctx.Locale.Language()),
		}

		ctx.JSON(http.StatusCreated, response)
	}
	return
}

// KitspaceSignIn custom sign-in compatible with Kitspace architecture
func KitspaceSignIn(ctx *context.Context, form auth.SignInForm) {
	// swagger:operation POST /user/kitspace/sign_in
	// ---
	// summary: login a user
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/SignInForm"
	// responses:
	//   "200":
	//     "$ref": "success"
	//   "404":
	//     "$ref": "#/response/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//	 "409":
	//     "$ref": "#/response/error
	//   "422":
	//     "$ref": "#/responses/validationError"

	u, err := models.UserSignIn(form.UserName, form.Password)

	response := make(map[string]string)
	if err != nil {
		switch {
		case models.IsErrUserNotExist(err):
			response["error"] = "Not Found"
			response["message"] = "Wrong username or password."

			ctx.JSON(http.StatusNotFound, response)
			log.Info("Failed authentication attempt for %s from %s", form.UserName, ctx.RemoteAddr())
		case models.IsErrEmailAlreadyUsed(err):
			response["error"] = "Conflict"
			response["message"] = "This email has already been used."

			ctx.JSON(http.StatusConflict, response)
			log.Info("Failed authentication attempt for %s from %s", form.UserName, ctx.RemoteAddr())
		case models.IsErrUserProhibitLogin(err):
			response["error"] = "Prohibited"
			response["message"] = "Prohibited login."

			ctx.JSON(http.StatusForbidden, response)
			log.Info("Failed authentication attempt for %s from %s", form.UserName, ctx.RemoteAddr())
		case models.IsErrUserInactive(err):
			if setting.Service.RegisterEmailConfirm {
				response["error"] = "ActivationRequired"
				response["message"] = "Activate your account."

				ctx.JSON(http.StatusOK, response)
			} else {
				response["error"] = "Prohibited"
				response["message"] = "Prohibited login"

				ctx.JSON(http.StatusForbidden, response)
				log.Info("Failed authentication attempt for %s from %s", form.UserName, ctx.RemoteAddr())
			}
		default:
			ctx.ServerError("KitspaceSignIn", err)
		}
		return
	}
	handleSignInFull(ctx, u, form.Remember, false)

	response["LoggedInSuccessfully"] = u.Name
	ctx.JSON(http.StatusOK, response)
}

func KitspaceSignOut(ctx *context.Context) {
	if ctx.User != nil {
		eventsource.GetManager().SendMessageBlocking(ctx.User.ID, &eventsource.Event{
			Name: "logout",
			Data: ctx.Session.ID(),
		})
	}

	handleSignOut(ctx)

	response := map[string]bool{"LoggedOutSuccessfully": true}
	ctx.JSON(http.StatusOK, response)
	return
}

// HandleSignOut resets the session and clear the cookies
func handleSignOut(ctx *context.Context) {
	_ = ctx.Session.Flush()
	_ = ctx.Session.Destroy(ctx.Context)
	ctx.SetCookie(
		setting.CookieUserName,
		"",
		-1,
		setting.AppSubURL,
		setting.SessionConfig.Domain,
		setting.SessionConfig.Secure,
		true)
	ctx.SetCookie(setting.CookieRememberName,
		"", -1,
		setting.AppSubURL,
		setting.SessionConfig.Domain,
		setting.SessionConfig.Secure,
		true)
	ctx.SetCookie(setting.CSRFCookieName,
		"",
		-1,
		setting.AppSubURL,
		setting.SessionConfig.Domain,
		setting.SessionConfig.Secure,
		true)
	ctx.SetCookie("lang",
		"",
		-1,
		setting.AppSubURL,
		setting.SessionConfig.Domain,
		setting.SessionConfig.Secure,
		true) // Setting the lang cookie will trigger the middleware to reset the language ot previous state.
}
