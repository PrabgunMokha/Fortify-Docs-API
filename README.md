# Fortify Docs API

A FastAPI service with a Streamlit interface for password-protecting PDFs, converting images into protected PDFs, and unlocking supported files with a password.

Files are processed in memory and returned as downloads. The application does not require a database or AI service.

## Features

- Password-protect PDFs using pikepdf AES-256 encryption (`R=6`).
- Apply PDF permission flags for printing, extraction, and modification.
- Convert JPG, JPEG, PNG, BMP, TIFF, TIF, GIF, and WebP inputs to protected PDFs.
- Unlock password-protected PDFs.
- Decrypt compatible `ENCFILE1` files through the unlock endpoint.
- Use Swagger API docs or the Streamlit upload/download interface.

## Setup

Use Python 3.10 or newer. From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

Open [API documentation](http://127.0.0.1:8000/docs). In a second terminal, activate the same environment and launch the UI:

```powershell
python -m streamlit run app.py
```

The UI normally opens at [localhost:8501](http://localhost:8501) and calls the API at `http://localhost:8000`.

## API

| Method | Route | Input |
| --- | --- | --- |
| GET | `/` | Service status and endpoint links |
| POST | `/api/v1/documents/protect` | Multipart `file`, `password`, optional `convert_to_pdf` |
| POST | `/api/v1/documents/unlock` | Multipart `file`, `password` |

Protection requires a password of at least four characters. Successful requests return file bytes with download headers. Incorrect-password failures in the unlock flow return HTTP 401.

### Protect a PDF

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/v1/documents/protect -F "file=@example.pdf" -F "password=replace-with-a-strong-password" -o protected.pdf
```

### Unlock a PDF

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/v1/documents/unlock -F "file=@protected.pdf" -F "password=replace-with-a-strong-password" -o unlocked.pdf
```

Use the interactive docs to inspect error responses when experimenting; the command examples save the response body directly.

## Project structure

- `main.py`: FastAPI routes, image conversion, and download responses.
- `app.py`: Streamlit client for protection and unlocking.
- `pdf_protection.py`: PDF encryption, permission flags, and unlocking.
- `encryption.py`: AES-256-CBC helpers with PBKDF2-HMAC-SHA256 key derivation and the custom `ENCFILE1` format.
- `requirements.txt`: API, UI, image, PDF, and cryptography dependencies.

