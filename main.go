package main

import (
	"database/sql"
	"encoding/json"
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

// CartItem represents an item in the cart.
type CartItem struct {
	ID        int `json:"id"`
	ProductID int `json:"product_id"`
	Quantity  int `json:"quantity"`
}

// AddCartItemRequest represents the JSON structure for adding a cart item.
type AddCartItemRequest struct {
	ProductID int `json:"product_id"`
	Quantity  int `json:"quantity"`
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

	// Cart endpoints:
	http.HandleFunc("/api/cart/create", createCartHandler)
	http.HandleFunc("/api/cart/clear", clearCartHandler)
	http.HandleFunc("/api/cart", getCartHandler)

	// Cart endpoint for adding an item.
	http.HandleFunc("/api/cart/add", addToCartHandler)

	log.Println("Server starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// homeHandler is a protected route. It checks for a "session" cookie.
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session cookie containing the user ID.
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	userID := sessionCookie.Value

	// Query the database to get the username using the user ID.
	var username string
	err = db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Query all products (no search term).
	products, err := queryProducts("")
	if err != nil {
		http.Error(w, "Error fetching products", http.StatusInternalServerError)
		return
	}

	data := HomePageData{
		Username: username,
		Products: products,
	}

	// Render the home page template.
	if err := tpl.ExecuteTemplate(w, "home.html", data); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
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

	// Set a cookie with the username (and/or user ID if desired)
	usernameCookie := &http.Cookie{
		Name:  "username",
		Value: username,
		Path:  "/",
		// Optional: set Secure, HttpOnly, etc.
	}
	http.SetCookie(w, usernameCookie)

	// Also set a session cookie with user ID if needed
	idCookie := &http.Cookie{
		Name:  "session",
		Value: strconv.Itoa(user.ID),
		Path:  "/",
	}
	http.SetCookie(w, idCookie)

	// Redirect to the home page
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
	// Retrieve the search term from the URL query parameters.
	q := r.URL.Query().Get("q")
	products, err := queryProducts(q)
	if err != nil {
		http.Error(w, "Error fetching products", http.StatusInternalServerError)
		return
	}

	// Try to retrieve the session cookie.
	sessionCookie, err := r.Cookie("session")
	var username string
	if err != nil {
		// If not logged in, set a default username.
		username = "Guest"
	} else {
		userID := sessionCookie.Value
		err = db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
		if err != nil {
			username = "Guest"
		}
	}

	data := HomePageData{
		Username: username,
		Products: products,
	}

	// Render the home page template with the filtered products.
	if err := tpl.ExecuteTemplate(w, "home.html", data); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

// createCartHandler creates a cart for the logged-in user if one does not exist.
func createCartHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session cookie (user ID)
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	userID := sessionCookie.Value

	// Check if a cart already exists for this user.
	var cartID int
	err = db.QueryRow("SELECT id FROM carts WHERE user_id = ?", userID).Scan(&cartID)
	if err == sql.ErrNoRows {
		// No cart exists; create one.
		res, err := db.Exec("INSERT INTO carts (user_id) VALUES (?)", userID)
		if err != nil {
			http.Error(w, "Error creating cart", http.StatusInternalServerError)
			return
		}
		id, err := res.LastInsertId()
		if err != nil {
			http.Error(w, "Error retrieving cart ID", http.StatusInternalServerError)
			return
		}
		cartID = int(id)
	} else if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Optionally, return the cart info as JSON.
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"cart_id": %d}`, cartID)
}

// clearCartHandler deletes all items in the user's cart.
func clearCartHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session cookie (user ID)
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	userID := sessionCookie.Value

	// Get the cart ID for the user.
	var cartID int
	err = db.QueryRow("SELECT id FROM carts WHERE user_id = ?", userID).Scan(&cartID)
	if err != nil {
		http.Error(w, "Cart not found", http.StatusNotFound)
		return
	}

	// Delete all items in the cart.
	_, err = db.Exec("DELETE FROM cart_items WHERE cart_id = ?", cartID)
	if err != nil {
		http.Error(w, "Error clearing cart", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getCartHandler retrieves all items in the user's cart.
func getCartHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session cookie (user ID)
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	userID := sessionCookie.Value

	// Get the cart ID for the user.
	var cartID int
	err = db.QueryRow("SELECT id FROM carts WHERE user_id = ?", userID).Scan(&cartID)
	if err != nil {
		http.Error(w, "Cart not found", http.StatusNotFound)
		return
	}

	// Query all items in the cart.
	rows, err := db.Query("SELECT id, product_id, quantity FROM cart_items WHERE cart_id = ?", cartID)
	if err != nil {
		http.Error(w, "Error fetching cart items", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var items []CartItem
	for rows.Next() {
		var item CartItem
		if err := rows.Scan(&item.ID, &item.ProductID, &item.Quantity); err != nil {
			http.Error(w, "Error scanning cart item", http.StatusInternalServerError)
			return
		}
		items = append(items, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

// addToCartHandler handles POST requests to /api/cart/add
func addToCartHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method.
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Retrieve the session cookie containing the user ID.
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	userID := sessionCookie.Value

	// Check if the user already has a cart. If not, create one.
	var cartID int
	err = db.QueryRow("SELECT id FROM carts WHERE user_id = ?", userID).Scan(&cartID)
	if err == sql.ErrNoRows {
		// Create a new cart for this user.
		res, err := db.Exec("INSERT INTO carts (user_id) VALUES (?)", userID)
		if err != nil {
			http.Error(w, "Error creating cart", http.StatusInternalServerError)
			return
		}
		id, err := res.LastInsertId()
		if err != nil {
			http.Error(w, "Error retrieving cart ID", http.StatusInternalServerError)
			return
		}
		cartID = int(id)
	} else if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Decode the JSON request body into our AddCartItemRequest struct.
	var reqData AddCartItemRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Insert the new cart item into the database.
	query := "INSERT INTO cart_items (cart_id, product_id, quantity) VALUES (?, ?, ?)"
	_, err = db.Exec(query, cartID, reqData.ProductID, reqData.Quantity)
	if err != nil {
		http.Error(w, "Error adding item to cart", http.StatusInternalServerError)
		return
	}

	// Respond with a success message.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Item added to cart successfully",
	})
}
