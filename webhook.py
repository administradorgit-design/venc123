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
HOTMART_SECRET = os.getenv("HOTMART_SECRET")

def validar_assinatura_hotmart(payload_bytes: bytes, assinatura_recebida: str) -> bool:
    """Valida que o webhook realmente veio da Hotmart."""
    if not HOTMART_SECRET:
        raise HTTPException(status_code=500, detail="Webhook não configurado: HOTMART_SECRET ausente")
    assinatura_esperada = hmac.new(
        HOTMART_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(assinatura_esperada, assinatura_recebida)

@router.post("/webhook/hotmart")
@limiter.limit("30/minute")
async def webhook_hotmart(request: Request):
    payload_bytes = await request.body()
    assinatura = request.headers.get("X-Hotmart-Hottok", "")

    # Valida se veio mesmo da Hotmart
    if not validar_assinatura_hotmart(payload_bytes, assinatura):
        raise HTTPException(status_code=401, detail="Assinatura inválida")

    dados = await request.json()

    # Verifica se é um evento de compra aprovada
    evento = dados.get("event", "")
    if evento not in ["PURCHASE_APPROVED", "PURCHASE_COMPLETE"]:
        return {"status": "ignorado", "evento": evento}

    # Pega o email do comprador
    try:
        email_aluno = dados["data"]["buyer"]["email"].lower().strip()
        nome_aluno = dados["data"]["buyer"].get("name", "")
    except KeyError:
        raise HTTPException(status_code=400, detail="Dados do comprador não encontrados")

    # Se já tem conta, não cria de novo
    if buscar_usuario(email_aluno):
        return {"status": "usuario_ja_existe", "email": email_aluno}

    # Gera senha temporária e cria o usuário
    senha_temp = gerar_senha_temporaria()
    senha_hash = hash_senha(senha_temp)

    sucesso, msg = criar_usuario(email_aluno, senha_hash, nome_aluno)
    if not sucesso:
        raise HTTPException(status_code=500, detail=f"Erro ao criar usuário: {msg}")

    # Envia email com as credenciais
    enviar_boas_vindas(email_aluno, senha_temp)

    return {"status": "ok", "email": email_aluno}