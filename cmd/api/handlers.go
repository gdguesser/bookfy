package main

import (
	"errors"
	"net/http"
	"time"
	"vue-api/internal/data"
)

type jsonResponse struct {
	Error   bool        `json:"error"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type envelope map[string]interface{}

func (app *application) Login(w http.ResponseWriter, r *http.Request) {
	type credentials struct {
		UserName string `json:"email"`
		Password string `json:"password"`
	}

	var creds credentials
	var payload jsonResponse

	err := app.readJSON(w, r, &creds)
	if err != nil {
		app.errorLog.Println(err)
		payload.Error = true
		payload.Message = "Invalid json supplied or json missing entirely"
		_ = app.writeJSON(w, http.StatusBadRequest, payload)
	}

	//TODO authenticate
	app.infoLog.Println(creds.UserName, creds.Password)

	//Lookup the user by email
	user, err := app.models.User.GetByEmail(creds.UserName)
	if err != nil {
		app.errorJSON(w, errors.New("Invalid username/password"))
		return
	}

	//Validate the users password
	validPassword, err := user.PasswordMatches(creds.Password)
	if err != nil || !validPassword {
		app.errorJSON(w, errors.New("Invalid username/password"))
		return
	}

	//if user valid, generate a token
	token, err := app.models.Token.GenerateToken(user.ID, 24*time.Hour)
	if err != nil {
		app.errorJSON(w, err)
		return
	}

	//save it to database
	err = app.models.Token.InsertToken(*token, *user)
	if err != nil {
		app.errorJSON(w, err)
		return
	}

	//send back a response
	payload = jsonResponse{
		Error:   false,
		Message: "Logged in",
		Data:    envelope{"token": token, "user": user},
	}

	err = app.writeJSON(w, http.StatusOK, payload)
	if err != nil {
		app.errorLog.Println(err)
	}
}

func (app *application) Logout(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Token string `json:"token"`
	}

	err := app.readJSON(w, r, &requestPayload)
	if err != nil {
		app.errorJSON(w, errors.New("Invalid json1"))
		return
	}

	err = app.models.Token.DeleteToken(requestPayload.Token)
	if err != nil {
		app.errorJSON(w, errors.New("Invalid json2"))
		return
	}

	payload := jsonResponse{
		Error:   false,
		Message: "Logged out",
	}

	_ = app.writeJSON(w, http.StatusOK, payload)
}

func (app *application) AllUsers(w http.ResponseWriter, r *http.Request) {
	var users data.User
	all, err := users.GetAll()
	if err != nil {
		app.errorLog.Println(err)
		return
	}

	payload := jsonResponse{
		Error:   false,
		Message: "success",
		Data:    envelope{"users": all},
	}

	app.writeJSON(w, http.StatusOK, payload) 
}
