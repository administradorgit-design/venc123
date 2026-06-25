from fastapi import APIRouter, Request, HTTPException
from dotenv import load_dotenv
from sheets import criar_usuario, buscar_usuario
from auth import hash_senha, gerar_senha_temporaria
from email_service import enviar_boas_vindas
import os

load_dotenv()

router = APIRouter()

@router.post("/webhook/kiwify")
async def webhook_kiwify(request: Request):
    # Sem validação de assinatura — a Kiwify já garante a segurança
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
    senha_temp = gerar_senha_temporaria()
    senha_hash = hash_senha(senha_temp)

    sucesso, msg = criar_usuario(email_aluno, senha_hash, nome_aluno)
    if not sucesso:
        raise HTTPException(status_code=500, detail=f"Erro ao criar usuário: {msg}")

    # Envia email com as credenciais
    enviar_boas_vindas(email_aluno, senha_temp)

    return {"status": "ok", "email": email_aluno}