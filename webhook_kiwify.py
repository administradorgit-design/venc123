import hmac
import hashlib
from fastapi import APIRouter, Request, HTTPException
from dotenv import load_dotenv
from sheets import criar_usuario, buscar_usuario
from auth import hash_senha, gerar_senha_temporaria
from email_service import enviar_boas_vindas
import os

load_dotenv()

router = APIRouter()
KIWIFY_SECRET = os.getenv("KIWIFY_SECRET", "")

def validar_assinatura_kiwify(payload_bytes: bytes, assinatura: str) -> bool:
    """Valida que o webhook veio mesmo da Kiwify."""
    if not KIWIFY_SECRET:
        return True  # sem secret configurado, aceita tudo (só em dev)
    esperada = hmac.new(
        KIWIFY_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha1
    ).hexdigest()
    return hmac.compare_digest(esperada, assinatura)

@router.post("/webhook/kiwify")
async def webhook_kiwify(request: Request):
    payload_bytes = await request.body()

    # Valida assinatura da Kiwify (vem como query param)
    assinatura = request.query_params.get("signature", "")
    if KIWIFY_SECRET and not validar_assinatura_kiwify(payload_bytes, assinatura):
        raise HTTPException(status_code=401, detail="Assinatura inválida")

    dados = await request.json()

    # Verifica se é compra aprovada
    status = dados.get("order_status", "")
    if status not in ["paid", "approved"]:
        return {"status": "ignorado", "order_status": status}

    # Pega o email e nome do comprador
    try:
        email_aluno = dados["Customer"]["email"].lower().strip()
        nome_aluno  = dados["Customer"].get("full_name", "").strip()
    except KeyError:
        raise HTTPException(status_code=400, detail="Dados do comprador não encontrados")

    # Se já tem conta, não cria de novo
    if buscar_usuario(email_aluno):
        return {"status": "usuario_ja_existe", "email": email_aluno}

    # Gera senha temporária e cria o usuário
    senha_temp  = gerar_senha_temporaria()
    senha_hash  = hash_senha(senha_temp)

    sucesso, msg = criar_usuario(email_aluno, senha_hash, nome_aluno)
    if not sucesso:
        raise HTTPException(status_code=500, detail=f"Erro ao criar usuário: {msg}")

    # Envia email com as credenciais
    enviar_boas_vindas(email_aluno, senha_temp)

    return {"status": "ok", "email": email_aluno}