# Compile the CA certificates for mitm in the proxy
FROM golang:1.22-bookworm AS ca-certs

# Set the working directory
WORKDIR /go/src/github.com/TheHackerDev/cartograph

# Fetch dependencies first; they are less susceptible to change on every build
# and will therefore be cached for speeding up the next build.
COPY ./go.mod ./go.sum ./
RUN go mod download

# Import the certificate files
COPY ./certificates/* ./cmd/ca-generator/* ./

RUN mkdir /certs

# Generate the CA certificates and keys to embed in the final build.
# RSA
RUN go run ./main.go -root-cert-in="/go/src/github.com/TheHackerDev/cartograph/root-cert-rsa.pem" \
                              -root-key-in="/go/src/github.com/TheHackerDev/cartograph/root-key-rsa.pem" \
                              -root-cert-der="/certs/root-cert-rsa.crt" \
                              -root-cert-pem="/certs/root-cert-rsa.pem" \
                              -root-key="/certs/root-key-rsa.pem" \
                              -intermediate-cert="/certs/intermediate-cert-rsa.pem" \
                              -intermediate-key="/certs/intermediate-key-rsa.pem"\
                              -rsa
# ECDSA
RUN go run ./main.go -root-cert-in="/go/src/github.com/TheHackerDev/cartograph/root-cert-ecdsa.pem" \
                              -root-key-in="/go/src/github.com/TheHackerDev/cartograph/root-key-ecdsa.pem" \
                              -root-cert-der="/certs/root-cert-ecdsa.crt" \
                              -root-cert-pem="/certs/root-cert-ecdsa.pem" \
                              -root-key="/certs/root-key-ecdsa.pem" \
                              -intermediate-cert="/certs/intermediate-cert-ecdsa.pem" \
                              -intermediate-key="/certs/intermediate-key-ecdsa.pem"

# Use buster, so we can have GCC built-in, which is required for the use
# of the race flag in go build.
FROM golang:1.22-bookworm

# Debug HTTP2 protocol
#ENV GODEBUG="http2debug=2"

# Declare the ports on which the application will be exposed.
# Port 8080 is for the proxy, 8000 is for the API, and 40000 is for Delve.
# Port 443 is for the Web UI, and port 80 redirects to 443 for the Web UI.
EXPOSE 8080 8000 40000 80 443/tcp

# Enable modules and CGO for compilation of Delve and cartograph
ENV GO111MODULE=on CGO_ENABLED=1

# Git is required for fetching the dependencies, and ca-certificates are used to
# make outbound HTTPS connections with a valid CA certificate pool.
# libc6-compat allows delve to run on Alpine based containers.
#RUN apk add --no-cache ca-certificates git libc6-compat

# Compile Delve
RUN go install github.com/go-delve/delve/cmd/dlv@latest

# Set the working directory
WORKDIR /go/src/github.com/TheHackerDev/cartograph

# Fetch dependencies first; they are less susceptible to change on every build
# and will therefore be cached for speeding up the next build.
COPY ./go.mod ./go.sum ./
RUN go mod download

# Import the code from the context.
COPY . .

# Copy over the generated CA certificates
COPY --from=ca-certs /certs/* internal/shared/http/certificates/

# Copy over the generated intermediate CA ECDSA certificate and key to be used for JWT signing
COPY --from=ca-certs /certs/intermediate-cert-ecdsa.pem /certs/intermediate-key-ecdsa.pem internal/shared/users/signing-certificates/

# Get the version of the binary from the build argument
#ARG version

# Build the executable to "/server"
# `-tags timetzdata` embeds zone info from the "time/tzdata" package.
# RUN go build -race -gcflags "all=-N -l" -ldflags "-X main.version=${version}" -o /cartograph ./cmd/cartograph/
RUN go build -race -gcflags "all=-N -l" -tags timetzdata -o /server ./cmd/cartograph/

# Run Delve, which calls cartograph, passing the mapper scripts directory as an argument.
ENTRYPOINT ["/go/bin/dlv", "--listen=:40000", "--headless=true", "--api-version=2", "--accept-multiclient", "--check-go-version=false", "exec", "/server", "--", "--training", "--mapper-script-dir", "/go/src/github.com/TheHackerDev/cartograph/internal/mapper"]