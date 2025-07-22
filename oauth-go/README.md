# OAuth Demo in Go

This is a Go version of the OAuth demo program.

## Prerequisites

- Go 1.18 or later

## Running the Demo

1.  Navigate to the `oauth-go` directory:

    ```bash
    cd oauth-go
    ```

2.  Run the application:

    ```bash
    go run main.go
    ```

This will start a local web server and open a browser window to the Looker authorization page. After you authorize the application, the tokens will be stored in `oauth_tokens.json`.
