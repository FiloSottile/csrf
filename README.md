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

## github.com/gorilla/csrf compatibility

The `filippo.io/csrf/gorilla` package provides a drop-in replacement for the
`github.com/gorilla/csrf` package. It implements the same API, but uses the
modern Fetch metadata headers instead of tokens and cookies.

Read the full [package documentation](https://pkg.go.dev/filippo.io/csrf/gorilla) for
full migration details.

```diff
 import (
+    csrf "filippo.io/csrf/gorilla"
-    "github.com/gorilla/csrf"
 )
```
