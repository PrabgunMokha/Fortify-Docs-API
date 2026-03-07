
import io
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image

from encryption import encrypt_file, decrypt_file, is_encrypted_file
from pdf_protection import protect_pdf, unlock_pdf, is_pdf

app = FastAPI(
    title="Password Secured File API",
    description="Secure your PDFs and Images with password-based protection. AES-256 encryption for images, PDF password protection with permission control.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".tif", ".gif", ".webp"}
PDF_EXTENSIONS = {".pdf"}


def _get_extension(filename: str) -> str:
    """Get lowercase file extension."""
    if "." in filename:
        return "." + filename.rsplit(".", 1)[1].lower()
    return ""


def _image_to_pdf_bytes(image_bytes: bytes) -> bytes:
    """Convert an image to PDF bytes using Pillow."""
    img = Image.open(io.BytesIO(image_bytes))
    if img.mode in ("RGBA", "LA", "P"):
        img = img.convert("RGB")
    output = io.BytesIO()
    img.save(output, format="PDF")
    output.seek(0)
    return output.read()




@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "Password Secured File API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "protect": "POST /api/v1/documents/protect",
            "unlock": "POST /api/v1/documents/unlock",
            "docs": "GET /docs",
        },
    }



@app.post("/api/v1/documents/protect", tags=["Protect"])
async def protect_document(
    file: UploadFile = File(..., description="PDF or Image file to protect"),
    password: str = Form(..., description="Password to protect the file"),
    convert_to_pdf: bool = Form(
        False, description="Convert image to PDF before protecting (optional)"
    ),
):
   
    if not password or len(password) < 4:
        raise HTTPException(
            status_code=400, detail="Password must be at least 4 characters"
        )

    file_bytes = await file.read()
    filename = file.filename or "document"
    ext = _get_extension(filename)
    base_name = filename.rsplit(".", 1)[0] if "." in filename else filename

    if ext in PDF_EXTENSIONS or is_pdf(file_bytes):
        try:
            protected = protect_pdf(file_bytes, password)
            return StreamingResponse(
                io.BytesIO(protected),
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{base_name}_protected.pdf"'
                },
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF protection failed: {str(e)}")


    elif ext in IMAGE_EXTENSIONS:
        try:
            pdf_bytes = _image_to_pdf_bytes(file_bytes)
            protected = protect_pdf(pdf_bytes, password)
            return StreamingResponse(
                io.BytesIO(protected),
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{base_name}_protected.pdf"'
                },
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Image protection failed: {str(e)}",
            )

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: '{ext}'. Supported: PDF, JPG, JPEG, PNG, BMP, TIFF, GIF, WebP",
        )



@app.post("/api/v1/documents/unlock", tags=["Unlock"])
async def unlock_document(
    file: UploadFile = File(..., description="Protected file to unlock"),
    password: str = Form(..., description="Password to unlock the file"),
):
   
    if not password:
        raise HTTPException(status_code=400, detail="Password is required")

    file_bytes = await file.read()
    filename = file.filename or "document"
    base_name = filename.rsplit(".", 1)[0] if "." in filename else filename

    
    if filename.lower().endswith(".enc") or is_encrypted_file(file_bytes):
        try:
            decrypted = decrypt_file(file_bytes, password)

            
            if filename.lower().endswith(".enc"):
                original_name = filename[:-4]
            else:
                original_name = f"{base_name}_unlocked"

            
            media_type = "application/octet-stream"
            if decrypted[:8] == b"\x89PNG\r\n\x1a\n":
                media_type = "image/png"
            elif decrypted[:2] == b"\xff\xd8":
                media_type = "image/jpeg"
            elif decrypted[:4] == b"GIF8":
                media_type = "image/gif"
            elif decrypted[:4] == b"RIFF" and decrypted[8:12] == b"WEBP":
                media_type = "image/webp"
            elif decrypted[:2] == b"BM":
                media_type = "image/bmp"

            return StreamingResponse(
                io.BytesIO(decrypted),
                media_type=media_type,
                headers={
                    "Content-Disposition": f'attachment; filename="{original_name}"'
                },
            )
        except ValueError as e:
            raise HTTPException(status_code=401, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

    elif is_pdf(file_bytes):
        try:
            unlocked = unlock_pdf(file_bytes, password)
            return StreamingResponse(
                io.BytesIO(unlocked),
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{base_name}_unlocked.pdf"'
                },
            )
        except ValueError as e:
            raise HTTPException(status_code=401, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF unlock failed: {str(e)}")

    else:
        raise HTTPException(
            status_code=400,
            detail="Cannot determine file type. Please upload a .enc (encrypted image) or password-protected .pdf file.",
        )


