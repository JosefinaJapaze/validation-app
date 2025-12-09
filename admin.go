package handlers

import (
	"eco-trip/pkg/model"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
)

// Credenciales hardcodeadas para admin
const (
	AdminUsername = "admin"
	AdminPassword = "admin123"
	AdminToken    = "admin-token-ecotrip-2024"
)

type AdminLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AdminLoginResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token"`
	User    struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"user"`
}

// AdminLogin maneja el login del administrador
func (h *handler) AdminLogin(w http.ResponseWriter, req *http.Request) {
	var loginReq AdminLoginRequest
	err := json.NewDecoder(req.Body).Decode(&loginReq)
	if err != nil {
		slog.Error("could not decode admin login request", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("could not decode request"))
		return
	}

	if loginReq.Username == AdminUsername && loginReq.Password == AdminPassword {
		resp := AdminLoginResponse{
			Success: true,
			Token:   AdminToken,
		}
		resp.User.Username = AdminUsername
		resp.User.Role = "validator"

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"message": "Credenciales inválidas",
	})
}

// ValidateAdminToken valida el token de admin
func ValidateAdminToken(token string) bool {
	return token == "Bearer "+AdminToken || token == AdminToken
}

// AdminAuthMiddleware middleware para validar el token de admin
func AdminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		token := req.Header.Get("Authorization")
		if !ValidateAdminToken(token) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"message": "No autorizado"})
			return
		}
		next(w, req)
	}
}

// PendingSubmissionWithUser representa una submission con datos del usuario
type PendingSubmissionWithUser struct {
	ID              int                            `json:"id"`
	UserID          int                            `json:"userId"`
	UserType        model.UserType                 `json:"userType"`
	Status          model.UserValidationSubmissionStatus `json:"status"`
	Name            string                         `json:"name"`
	Email           string                         `json:"email"`
	CreatedAt       string                         `json:"createdAt,omitempty"`
	DNIKey          string                         `json:"dniKey"`
	GoodBehaviorKey string                         `json:"goodBehaviorKey"`
	DriverLicenseKey string                        `json:"driverLicenseKey"`
	GreenCardKey    string                         `json:"greenCardKey"`
	InsuranceKey    string                         `json:"insuranceKey"`
	LicensePlateKey string                         `json:"licensePlateKey"`
	ExampleInvoiceKey string                       `json:"exampleInvoiceKey"`
	SelfPhotoKey    string                         `json:"selfPhotoKey"`
}

// GetPendingSubmissions obtiene todas las submissions pendientes
func (h *handler) GetPendingSubmissions(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	submissions, err := h.Database.ListAllPendingSubmissions(ctx)
	if err != nil {
		slog.Error("could not get pending submissions", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"message": "Error al obtener submissions"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": submissions,
	})
}

// SubmissionFile representa un archivo de una submission
type SubmissionFile struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	URL          string `json:"url"`
	DocumentType string `json:"documentType"`
}

// GetSubmissionFiles obtiene los archivos de una submission
func (h *handler) GetSubmissionFiles(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// Obtener submissionId del query param
	submissionIDStr := req.URL.Query().Get("submissionId")
	if submissionIDStr == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "submissionId es requerido"})
		return
	}

	submissionID, err := strconv.Atoi(submissionIDStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "submissionId inválido"})
		return
	}

	submission, err := h.Database.GetUserSubmission(ctx, submissionID)
	if err != nil {
		slog.Error("could not get submission", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "Submission no encontrada"})
		return
	}

	// Generar URLs presignadas para cada documento
	var files []SubmissionFile

	// Helper para agregar archivo si tiene key
	addFile := func(key, name, docType string) {
		if key == "" {
			return
		}
		url, err := h.Bucket.GeneratePreSignedURL(ctx, key)
		if err != nil {
			slog.Error("could not generate presigned url", slog.String("key", key), slog.String("error", err.Error()))
			return
		}

		fileType := "image"
		if len(key) > 4 && key[len(key)-4:] == ".pdf" {
			fileType = "pdf"
		}

		files = append(files, SubmissionFile{
			Key:          key,
			Name:         name,
			Type:         fileType,
			URL:          url,
			DocumentType: docType,
		})
	}

	addFile(submission.DNIKey, "DNI", "dni")
	addFile(submission.SelfPhotoKey, "Selfie", "self_photo")
	addFile(submission.GoodBehaviorKey, "Certificado de Buena Conducta", "good_behavior")
	addFile(submission.ExampleInvoiceKey, "Comprobante de Domicilio", "example_invoice")

	// Documentos adicionales para conductores
	if submission.UserType == model.UserTypeDriver {
		addFile(submission.DriverLicenseKey, "Licencia de Conducir", "driver_license")
		addFile(submission.GreenCardKey, "Tarjeta Verde", "green_card")
		addFile(submission.InsuranceKey, "Seguro", "insurance")
		addFile(submission.LicensePlateKey, "Patente", "license_plate")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"files": files,
	})
}

// ApproveSubmissionRequest representa la request para aprobar una submission
type ApproveSubmissionRequest struct {
	SubmissionID int `json:"submissionId"`
}

// ApproveSubmission aprueba una submission y valida al usuario
func (h *handler) ApproveSubmission(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	var approveReq ApproveSubmissionRequest
	err := json.NewDecoder(req.Body).Decode(&approveReq)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Request inválida"})
		return
	}

	// Obtener la submission
	submission, err := h.Database.GetUserSubmission(ctx, approveReq.SubmissionID)
	if err != nil {
		slog.Error("could not get submission", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "Submission no encontrada"})
		return
	}

	// Actualizar status de la submission a approved
	submission.Status = model.UserValidationSubmissionStatusApproved
	_, err = h.Database.UpdateUserSubmission(ctx, submission)
	if err != nil {
		slog.Error("could not update submission", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"message": "Error al actualizar submission"})
		return
	}

	// Actualizar el usuario como validado
	user, err := h.Database.GetUserDetails(ctx, submission.UserID)
	if err != nil {
		slog.Error("could not get user", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"message": "Error al obtener usuario"})
		return
	}

	user.Validated = true
	_, err = h.Database.UpdateUserDetails(ctx, user)
	if err != nil {
		slog.Error("could not update user", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"message": "Error al validar usuario"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Usuario validado correctamente",
	})
}

// RejectSubmissionRequest representa la request para rechazar una submission
type RejectSubmissionRequest struct {
	SubmissionID int    `json:"submissionId"`
	Reason       string `json:"reason"`
}

// RejectSubmission rechaza una submission
func (h *handler) RejectSubmission(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	var rejectReq RejectSubmissionRequest
	err := json.NewDecoder(req.Body).Decode(&rejectReq)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Request inválida"})
		return
	}

	// Obtener la submission
	submission, err := h.Database.GetUserSubmission(ctx, rejectReq.SubmissionID)
	if err != nil {
		slog.Error("could not get submission", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "Submission no encontrada"})
		return
	}

	// Actualizar status de la submission a rejected
	submission.Status = model.UserValidationSubmissionStatusRejected
	_, err = h.Database.UpdateUserSubmission(ctx, submission)
	if err != nil {
		slog.Error("could not update submission", slog.String("error", err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"message": "Error al actualizar submission"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Submission rechazada",
	})
}

