

import io
import secrets
import string
import pikepdf


def _generate_owner_password(length: int = 32) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def protect_pdf(file_bytes: bytes, user_password: str) -> bytes:
    owner_password = _generate_owner_password()

    pdf = pikepdf.open(io.BytesIO(file_bytes))

    permissions = pikepdf.Permissions(
        print_lowres=False,
        print_highres=False,
        extract=False,
        modify_annotation=False,
        modify_form=False,
        modify_assembly=False,
        modify_other=False,
    )

    pdf.save(
        output := io.BytesIO(),
        encryption=pikepdf.Encryption(
            user=user_password,
            owner=owner_password,
            R=6,  # AES-256
            allow=permissions,
        ),
    )
    output.seek(0)
    return output.read()


def unlock_pdf(file_bytes: bytes, password: str) -> bytes:

    try:
        pdf = pikepdf.open(io.BytesIO(file_bytes), password=password)


        output = io.BytesIO()
        pdf.save(output)
        output.seek(0)
        return output.read()

    except pikepdf.PasswordError:
        raise ValueError("Incorrect password: cannot unlock this PDF")
    except Exception as e:
        raise ValueError(f"Failed to unlock PDF: {str(e)}")


def is_pdf(file_bytes: bytes) -> bool:

    return file_bytes[:5] == b"%PDF-"
