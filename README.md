This is a simple Tiktok e-commerce platform.

Below are the functions:

- Verification
- Signup / login / collecting Users' data
- Querying product infomation
- Cart
- Order
- Statements
- Payment

Here is a simple HTTP server in Go generated by ChatGPT:

```go
package main

import (
    "fmt"
    "net/http"
    "time"
)

func main() {
    // Route for the root path
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Welcome to My Go Server!")
    })

    // Route for the /hello/{name} path
    http.HandleFunc("/hello/", func(w http.ResponseWriter, r *http.Request) {
        name := r.URL.Path[len("/hello/"):]
        if name == "" {
            name = "Guest"
        }
        fmt.Fprintf(w, "Hello, %s!", name)
    })

    // Route for the /time path
    http.HandleFunc("/time", func(w http.ResponseWriter, r *http.Request) {
        currentTime := time.Now().Format("2006-01-02 15:04:05")
        fmt.Fprintf(w, "Current server time: %s", currentTime)
    })

    // Start the server on port 8080
    fmt.Println("Server is running on http://localhost:8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        fmt.Println("Error starting server:", err)
    }
}
```

#### How to create, query or update a product (in CMD)

##### Create

```cmd
curl --header "Content-Type: application/json" --request POST --data @products\2.json http://localhost:8080/api/products
```

##### Query All

```cmd
curl  http://localhost:8080/api/products
```

##### Query One

```cmd
curl  http://localhost:8080/api/products/3
```

##### Update

```cmd
curl --header "Content-Type: application/json" --request PUT --data @products\4.json http://localhost:8080/api/products/4
```