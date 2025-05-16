# filippo.io/csrf

This package provides protection against Cross-Site Request Forgery (CSRF)
attacks using modern browser Fetch metadata headers.

It requires no tokens or cookies, and works with all browsers since 2020.

```go
package main

import (
    "net/http"
    "filippo.io/csrf"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Hello, world!")
    })

    protection := csrf.New()
    handler := protection.Handler(mux)
    
    http.ListenAndServe(":8080", handler)
}
```

For full API documentation, including bypass mechanisms, see [pkg.go.dev](https://pkg.go.dev/filippo.io/csrf).

For more information on this approach, see [the standard library proposal](https://go.dev/issue/73626).
