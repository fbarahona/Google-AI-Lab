# Extra CA certificates (optional)

Only needed behind a TLS-inspecting proxy, such as a corporate network running
Docker Desktop. Drop the proxy's root certificate here (`.crt` or `.cer`, PEM or
DER) and rebuild the container; the Dockerfile adds it to the system trust store.

GitHub Codespaces does not need anything here. Certificate files in this folder are
gitignored so a company's CA never lands in the repo.
