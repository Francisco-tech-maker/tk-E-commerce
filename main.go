package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var (
	db  *sql.DB
	tpl *template.Template
)

// User represents a user account.
type User struct {
	ID       int
	Username string
	Password string // stored as a bcrypt hash
}

type HomePageData struct {
	Username string
	Products []Product
}

func init() {
	// Parse all templates from the "templates" directory.
	tpl = template.Must(template.ParseGlob("templates/*.html"))
}

func main() {
	// Connect to MySQL.
	// Adjust the DSN ("user:password@tcp(host:port)/dbname") as needed.
	var err error
	dsn := "root:@wG}/HTi>@61<@tcp(127.0.0.1:3306)/shoppingmall"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to MySQL!")

	// Routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	// New API endpoint from the functions in userapi.go:
	http.HandleFunc("/api/users", GetUsersHandler)

	http.HandleFunc("/api/products", func(w http.ResponseWriter, r *http.Request) {
		// Use different handler functions based on the request method.
		switch r.Method {
		case http.MethodGet:
			getProductsHandler(w, r)
		case http.MethodPost:
			createProductHandler(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	// Endpoints with ID in URL for GET, PUT, DELETE.
	http.HandleFunc("/api/products/", func(w http.ResponseWriter, r *http.Request) {
		// Determine method.
		switch r.Method {
		case http.MethodGet:
			getProductHandler(w, r)
		case http.MethodPut:
			updateProductHandler(w, r)
		case http.MethodDelete:
			deleteProductHandler(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

	// Endpoint for product queries (for search form)
	http.HandleFunc("/api/products/query", queryProductsHandler)

	log.Println("Server starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// homeHandler is a protected route. It checks for a "session" cookie.
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session cookie.
	// Assume the user is authenticated and a session cookie "session" contains their user ID.
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	userID := cookie.Value
	var username string
	err = db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Query all products (or adjust if you want a default search term)
	products, err := queryProducts("")
	if err != nil {
		http.Error(w, "Error fetching products", http.StatusInternalServerError)
		return
	}

	data := HomePageData{
		Username: username,
		Products: products,
	}

	// Render home page with the username.
	tpl.ExecuteTemplate(w, "home.html", data)
}

// signupHandler allows users to create an account.
func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Show signup form.
		tpl.ExecuteTemplate(w, "signup.html", nil)
		return
	}

	// POST: Process form submission.
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "Missing username or password", http.StatusBadRequest)
		return
	}

	// Hash the password.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Insert the new user into the database.
	res, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
	if err != nil {
		http.Error(w, "Error creating account", http.StatusInternalServerError)
		return
	}
	id, err := res.LastInsertId()
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Automatically log in the user by setting a cookie.
	cookie := &http.Cookie{
		Name:  "session",
		Value: fmt.Sprintf("%d", id),
		Path:  "/",
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// loginHandler verifies user credentials and sets a session cookie.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Optionally, fetch products to display on the login page.
		products, err := queryProducts("")
		if err != nil {
			http.Error(w, "Error fetching products", http.StatusInternalServerError)
			return
		}
		data := HomePageData{
			Username: "", // No username for the login page.
			Products: products,
		}
		tpl.ExecuteTemplate(w, "login.html", data)
		return
	}

	// POST branch: process login credentials...
	// POST: Process login.
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "Missing username or password", http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Compare the hashed password with the entered password.
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Set session cookie.
	cookie := &http.Cookie{
		Name:  "session",
		Value: strconv.Itoa(user.ID),
		Path:  "/",
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logoutHandler clears the session cookie.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // delete cookie
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func queryProducts(q string) ([]Product, error) {
	var rows *sql.Rows
	var err error
	if q == "" {
		rows, err = db.Query("SELECT id, name, description, price FROM products")
	} else {
		q = "%" + q + "%"
		rows, err = db.Query("SELECT id, name, description, price FROM products WHERE name LIKE ?", q)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price); err != nil {
			return nil, err
		}
		products = append(products, p)
	}
	return products, nil
}

func queryProductsHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the query parameter "q" from the URL.
	q := r.URL.Query().Get("q")
	products, err := queryProducts(q)
	if err != nil {
		http.Error(w, "Error fetching products", http.StatusInternalServerError)
		return
	}
	// Render the same home template with the filtered products.
	// For this example, we'll assume the user is already logged in and we have their username.
	// In a real app, you might retrieve this from the session.
	data := HomePageData{
		Username: "CurrentUser", // Replace with actual username from session
		Products: products,
	}
	tpl.ExecuteTemplate(w, "home.html", data)
}
