import stripe
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
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")


@router.post("/webhook/stripe")
async def webhook_stripe(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Webhook não configurado: STRIPE_WEBHOOK_SECRET ausente")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Payload inválido")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=401, detail="Assinatura inválida")

    if event["type"] != "checkout.session.completed":
        return {"status": "ignorado", "evento": event["type"]}

    session = event["data"]["object"]
    email_aluno = session.get("customer_details", {}).get("email", "").lower().strip()
    nome_aluno = session.get("customer_details", {}).get("name", "").strip()

    if not email_aluno:
        raise HTTPException(status_code=400, detail="Email do comprador não encontrado")

    if buscar_usuario(email_aluno):
        return {"status": "usuario_ja_existe", "email": email_aluno}

    senha_temp = gerar_senha_temporaria()
    senha_hash = hash_senha(senha_temp)

    sucesso, msg = criar_usuario(email_aluno, senha_hash, nome_aluno)
    if not sucesso:
        raise HTTPException(status_code=500, detail=f"Erro ao criar usuário: {msg}")

    enviar_boas_vindas(email_aluno, senha_temp)

    return {"status": "ok", "email": email_aluno}
