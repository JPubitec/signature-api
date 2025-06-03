from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
import base64
import io
import logging

from processing import (
    cargar_clave_privada,
    cargar_clave_publica,
    firmar_docx,
    insertar_firma_en_docx,
    verificar_firma_docx
)

app = FastAPI()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =======================
# MODELO PARA JSON INPUT
# =======================

class FirmaJsonRequest(BaseModel):
    archivo_b64: str
    nombre_usuario: str

# =======================
# ENDPOINT: Firma usando JSON (para Power Automate)
# =======================

@app.post("/firmar_json/")
async def firmar_json(data: FirmaJsonRequest):
    try:
        contenido = base64.b64decode(data.archivo_b64)
        if not contenido:
            raise HTTPException(status_code=400, detail="El archivo base64 está vacío.")

        private_key = cargar_clave_privada()
        firma = firmar_docx(contenido, private_key)
        firma_b64 = base64.b64encode(firma).decode("utf-8")

        return {
            "firma_base64": firma_b64,
            "usuario": data.nombre_usuario
        }

    except Exception as e:
        logger.error(f"Error en /firmar_json/: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

# =======================
# ENDPOINT: Firma tradicional con multipart/form-data
# =======================

@app.post("/firmar/")
async def firmar(
    archivo: UploadFile = File(...),
    nombre_usuario: str = Form(...)
):
    try:
        contenido = await archivo.read()
        if not contenido:
            raise HTTPException(status_code=400, detail="El archivo está vacío.")

        private_key = cargar_clave_privada()
        firma = firmar_docx(contenido, private_key)
        firma_b64 = base64.b64encode(firma).decode("utf-8")

        return {
            "nombre_archivo": archivo.filename,
            "firma_base64": firma_b64,
            "usuario": nombre_usuario
        }

    except Exception as e:
        logger.error(f"Error en /firmar/: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

# =======================
# ENDPOINT: Verificar firma
# =======================

@app.post("/verificar/")
async def verificar(
    archivo: UploadFile = File(...),
    firma_b64: str = Form(...)
):
    try:
        contenido = await archivo.read()
        if not contenido:
            raise HTTPException(status_code=400, detail="El archivo está vacío.")

        public_key = cargar_clave_publica()
        valido = verificar_firma_docx(contenido, firma_b64, public_key)

        return {
            "nombre_archivo": archivo.filename,
            "firma_valida": valido
        }

    except Exception as e:
        logger.error(f"Error en /verificar/: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

# =======================
# ENDPOINT: Firmar e insertar firma en el .docx
# =======================

@app.post("/firmar-docx/")
async def firmar_y_insertar(
    archivo: UploadFile = File(...),
    nombre_usuario: str = Form(...)
):
    try:
        contenido = await archivo.read()
        if not contenido:
            raise HTTPException(status_code=400, detail="El archivo está vacío.")

        private_key = cargar_clave_privada()
        firma = firmar_docx(contenido, private_key)
        firma_b64 = base64.b64encode(firma).decode("utf-8")

        docx_firmado = insertar_firma_en_docx(contenido, firma_b64)
        nombre_firmado = f"{archivo.filename.replace('.docx', '')}_firmado.docx"

        return StreamingResponse(
            io.BytesIO(docx_firmado),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename={nombre_firmado}"}
        )

    except Exception as e:
        logger.error(f"Error en /firmar-docx/: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")
