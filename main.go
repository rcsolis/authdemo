package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

const PORT = ":5000"

const URL_JWKS = "https://login.microsoftonline.com/cbd68324-7a75-4a19-a711-81dfd37e3ece/discovery/keys?appid=323d2ffd-0781-4c18-a725-fa643e5cad3d"

type JWTCustomClaims struct {
	Appid      string   `json:"appid"`
	Email      string   `json:"email"`
	FamilyName string   `json:"family_name"`
	GivenName  string   `json:"given_name"`
	Name       string   `json:"name"`
	Oid        string   `json:"oid"`
	Roles      []string `json:"roles"`
	Scp        string   `json:"scp"`
	Sid        string   `json:"sid"`
	UniqueName string   `json:"unique_name"`
	Upn        string   `json:"upn"`
	jwt.RegisteredClaims
}

// For add a status code to the response writer if needed
type wrappedResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// CORS Middleware
func corsHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the headers
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Vary", "Access-Control-Request-Method")
		w.Header().Set("Vary", "Access-Control-Request-Headers")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Origin, Accept")
		// Handle the preflight request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware for logging the request
func loggingRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrappedWriter := &wrappedResponseWriter{w, http.StatusOK}
		next.ServeHTTP(wrappedWriter, r)
		log.Println("Logging::Request: ", wrappedWriter.statusCode, r.Method, r.URL.Path, time.Since(start))
	})
}

// Middleware for validating the token
func validateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		log.Println("Authorization Header: ", authorization)
		if !strings.HasPrefix(authorization, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			return
		}
		tokenStr := strings.TrimPrefix(authorization, "Bearer ")
		if tokenStr == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			return
		}
		// Create a context that, when cancelled, ends the JWKS background refresh goroutine.
		ctx, cancel := context.WithCancel(context.Background())
		// Create the keyfunc.Keyfunc.
		k, err := keyfunc.NewDefaultCtx(ctx, []string{URL_JWKS}) // Context is used to end the refresh goroutine.
		if err != nil {
			log.Fatalf("Failed to create a keyfunc.Keyfunc from the server's URL.\nError: %s", err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			cancel()
			return
		}
		// Parse the JWT.
		var token *jwt.Token
		//if token, err = jwt.Parse(tokenStr, k.KeyfuncCtx(ctx)); err != nil {
		if token, err = jwt.ParseWithClaims(tokenStr, &JWTCustomClaims{}, k.KeyfuncCtx(ctx)); err != nil {
			log.Fatalf("Failed to parse the JWT.\nError: %s", err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			cancel()
			return
		}
		// Check if the token is valid.
		switch {
		case token.Valid:
			log.Println("Token Valid!")
		case errors.Is(err, jwt.ErrTokenMalformed):
			log.Fatalf("The token MALFORMED.")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			cancel()
			return
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			log.Fatalf("The token has an INVALID SIGNATURE.")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			cancel()
			return
		case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
			// Token is either expired or not active yet
			log.Fatalf("The token is EXPIRED.")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			cancel()
			return
		default:
			log.Fatalf("TOKEN UNKNOWN.")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			cancel()
			return
		}
		claims, ok := token.Claims.(*JWTCustomClaims)
		if !ok {
			log.Fatalf("The token claims are not valid.")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			cancel()
			return
		}
		log.Println("Parsed Token claims: ")
		log.Println("ID: ", claims.ID)
		log.Println("Issuer: ", claims.Issuer)
		log.Println("Audience: ", claims.Audience)
		log.Println("ExpiresAt: ", claims.ExpiresAt)
		log.Println("NotBefore: ", claims.NotBefore)
		log.Println("IssuedAt: ", claims.IssuedAt)
		log.Println("ID: ", claims.ID)
		log.Println("Subject: ", claims.Subject)
		log.Println("--------------------")
		log.Println("Appid: ", claims.Appid)
		log.Println("Email: ", claims.Email)
		log.Println("FamilyName: ", claims.FamilyName)
		log.Println("GivenName: ", claims.GivenName)
		log.Println("Name: ", claims.Name)
		log.Println("Oid: ", claims.Oid)
		log.Println("Roles: ", claims.Roles)
		log.Println("Scp: ", claims.Scp)
		log.Println("Sid: ", claims.Sid)
		log.Println("UniqueName: ", claims.UniqueName)
		log.Println("Upn: ", claims.Upn)
		// End the background refresh goroutine when it's no longer needed.
		cancel()
		r.Header.Set("X-Role", claims.Roles[0])
		next.ServeHTTP(w, r)
	})
}

// Type Middleware for create middleware stack
type Middleware func(http.Handler) http.Handler

// Function for create the middleware stack
func createStack(m ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(m) - 1; i >= 0; i-- {
			n := m[i]
			next = n(next)
		}
		return next
	}
}

// Main function
func main() {
	// Create the middleware stack
	middlewareStack := createStack(
		loggingRequest,
		//validateToken,
		corsHeaders,
	)
	// Create private router
	privateRouter := http.NewServeMux()
	privateRouter.HandleFunc("GET /all", secureHandler)
	privateRouter.HandleFunc("GET /owner", onlyOwnerHandler)
	// Create public router
	publicRouter := http.NewServeMux()
	publicRouter.HandleFunc("GET /nosecure", homeHandler)
	// Add private router to public router with validate token middleware
	publicRouter.Handle("GET /secure/", http.StripPrefix("/secure", validateToken(privateRouter)))

	// Base router
	baseRouter := http.NewServeMux()
	baseRouter.Handle("/api/", http.StripPrefix("/api", publicRouter))
	// Create the server with the middleware stack
	server := &http.Server{
		Addr:    PORT,
		Handler: middlewareStack(baseRouter),
	}
	// Start the server
	log.Print("Starting server on port", PORT, "...")
	server.ListenAndServe()
}

// Public Handler
func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Public Endpoint, you are not autenticated!"))
}

// Private Handler
func secureHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("SecureHandler X-Role:", r.Header.Get("X-Role"))
	w.Write([]byte("Secure Ednpoint, you are autenticated!"))
}

func onlyOwnerHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("OnlyOwnerHandler X-Role:", r.Header.Get("X-Role"))
	if r.Header.Get("X-Role") != "owner" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Only Owner Ednpoint, you are not autenticated!"))
		return
	}
	w.Write([]byte("Only Owner Ednpoint, you are autenticated!"))
}
