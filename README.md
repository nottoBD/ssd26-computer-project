# Secure Medical Records System

## Group Members

| Matricule | Name              |
|-----------|-------------------|
| 519237    | Peetroons Simon   |
| 604350    | Andrianirina Mino |
| 615056    | Botton David      |
| 616822    | Gerday Léandre    |
| 617441    | Varga Ferenc      |

## Prerequisites

To build and run this project, you must fulfill certain requirements:
- Docker
- Docker Buildx
- Docker Compose
- Make
- Python 3.10 or newer
- QR code reader (ie: CoBang Linux)
- Web browser (Chrome-based for its Webauthn DevTool)
- Windows Hello or any browser Password Manager (for Linux & non-PRF enabled devices)

The project is designed to build and run on an x64 Ubuntu 22.04 distribution or an x64 Windows 10 machine.

## Building and Running the Project

1. Clone the repository to your local machine.

2. Navigate to the project root directory.

3. Run the following command from project's root to build and launch the project:

```
make
```

This will execute three scripts in sequence:
- `reset`: Resets the environment.
- `pki`: Sets up the Public Key Infrastructure.
- `run`: Starts the containers.

If the `make` command fails (container not running or malformed pki/ tree structure), it might be due to a poor internet connection. Try `make` again with a stable connection.

4. To restart the containers without resetting or regenerating the PKI, use:

```
make run
```


## How to Use the Project

Once the project is running via Docker containers:

- Add step-root.pem (Root CA) to your Chrome browser's trust store.
- The platform will be accessible at `https://healthsecure.local:3443` (nginx port). 

Detailed usage examples and report can be found in the `docs/` directory.


## Notes

- This project implements a secure client/server system for handling medical records, focusing on security aspects such as confidentiality, integrity, authentication, and non-repudiation.
- All sensitive data is handled securely: encrypted in transit and at rest, with the server not trusted for sensitive information.
- The system uses a PKI with a chain of trust for certificate validation.
- Logs are implemented for monitoring user activity, with input sanitization and anomaly detection.
- Only security and compliance with the project instructions are prioritized; web-development best practices are followed only where they impact security or efficiency.
