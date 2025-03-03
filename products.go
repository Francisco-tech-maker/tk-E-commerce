package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Product represents a product in your shopping mall.
type Product struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
}

// createProductHandler handles POST /api/products
func createProductHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure that the request method is POST.
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var p Product
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	query := "INSERT INTO products (name, description, price) VALUES (?, ?, ?)"
	result, err := db.Exec(query, p.Name, p.Description, p.Price)
	if err != nil {
		http.Error(w, "Error inserting product", http.StatusInternalServerError)
		return
	}
	id, err := result.LastInsertId()
	if err != nil {
		http.Error(w, "Error retrieving product ID", http.StatusInternalServerError)
		return
	}
	p.ID = int(id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

// getProductsHandler handles GET /api/products
func getProductsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, description, price FROM products")
	if err != nil {
		http.Error(w, "Error querying products", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price); err != nil {
			http.Error(w, "Error scanning product", http.StatusInternalServerError)
			return
		}
		products = append(products, p)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(products)
}

// getProductHandler handles GET /api/products/{id}
func getProductHandler(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/products/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}
	var p Product
	err = db.QueryRow("SELECT id, name, description, price FROM products WHERE id = ?", id).
		Scan(&p.ID, &p.Name, &p.Description, &p.Price)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Product not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error fetching product", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

// updateProductHandler handles PUT /api/products/{id}
func updateProductHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/api/products/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}

	var p Product
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	query := "UPDATE products SET name = ?, description = ?, price = ? WHERE id = ?"
	_, err = db.Exec(query, p.Name, p.Description, p.Price, id)
	if err != nil {
		http.Error(w, "Error updating product", http.StatusInternalServerError)
		return
	}
	p.ID = id
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

// deleteProductHandler handles DELETE /api/products/{id}
func deleteProductHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/products/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}
	query := "DELETE FROM products WHERE id = ?"
	_, err = db.Exec(query, id)
	if err != nil {
		http.Error(w, "Error deleting product", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
