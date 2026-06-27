import hmac
import hashlib
from fastapi import APIRouter, Request, HTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address
from dotenv import load_dotenv
from sheets import criar_usuario, buscar_usuario
from auth import hash_senha, gerar_senha_temporaria
from email_service import enviar_boas_vindas
import os

load_dotenv()

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
KIWIFY_SECRET = os.getenv("KIWIFY_SECRET")

def validar_assinatura_kiwify(payload_bytes: bytes, assinatura_recebida: str) -> bool:
    """Valida que o webhook realmente veio da Kiwify."""
    if not KIWIFY_SECRET:
        raise HTTPException(status_code=500, detail="Webhook não configurado: KIWIFY_SECRET ausente")
    assinatura_esperada = hmac.new(
        KIWIFY_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(assinatura_esperada, assinatura_recebida)

@router.post("/webhook/kiwify")
@limiter.limit("30/minute")
async def webhook_kiwify(request: Request):
    payload_bytes = await request.body()
    assinatura = request.headers.get("x-kiwify-signature", "")

    if not validar_assinatura_kiwify(payload_bytes, assinatura):
        raise HTTPException(status_code=401, detail="Assinatura inválida")

    dados = await request.json()

    status = dados.get("order_status", "")
    if status not in ["paid", "approved"]:
        return {"status": "ignorado", "order_status": status}

    try:
        email_aluno = dados["Customer"]["email"].lower().strip()
        nome_aluno  = dados["Customer"].get("full_name", "").strip()
    except KeyError:
        raise HTTPException(status_code=400, detail="Dados do comprador não encontrados")

    if buscar_usuario(email_aluno):
        return {"status": "usuario_ja_existe", "email": email_aluno}

    senha_temp = gerar_senha_temporaria()
    senha_hash = hash_senha(senha_temp)

    sucesso, msg = criar_usuario(email_aluno, senha_hash, nome_aluno)
    if not sucesso:
        raise HTTPException(status_code=500, detail=f"Erro ao criar usuário: {msg}")

    enviar_boas_vindas(email_aluno, senha_temp)

    return {"status": "ok", "email": email_aluno}
