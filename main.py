from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
from auth import verificar_senha, gerar_token, verificar_token, hash_senha, gerar_senha_temporaria
from sheets import (
    buscar_usuario, atualizar_senha,
    listar_aulas, buscar_link_aula,
    buscar_progresso, salvar_progresso,
    buscar_descricao_aula
)
from email_service import enviar_recuperacao_senha
from webhook import router as webhook_router
from webhook_stripe import router as stripe_router
import stripe
import os

load_dotenv()

# ── Rate limiter ──────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="UniDatas API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ──────────────────────────────────────
cors_origins_env = os.getenv("CORS_ORIGINS", "")
if cors_origins_env:
    CORS_ORIGINS = [o.strip() for o in cors_origins_env.split(",") if o.strip()]
else:
    CORS_ORIGINS = [
        "https://unidatas.com.br",
        "https://www.unidatas.com.br"
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ── Security headers ──────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.plyr.io; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.plyr.io; "
        "font-src 'self' https://fonts.gstatic.com; "
        "frame-src 'self' https://www.youtube.com https://youtube.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://venc123-production.up.railway.app https://unidatas.com.br; "
        "media-src 'self' https://cdn.plyr.io"
    )
    return response

# ── Webhook routers ───────────────────────────
app.include_router(webhook_router)
app.include_router(stripe_router)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "")
STRIPE_CURRENCY = os.getenv("STRIPE_CURRENCY", "BRL")

# ── Schemas ───────────────────────────────────
class LoginSchema(BaseModel):
    email: EmailStr
    password: str

class RecuperacaoSchema(BaseModel):
    email: EmailStr

class TrocarSenhaSchema(BaseModel):
    senha_atual: str
    nova_senha: str

class ProgressoSchema(BaseModel):
    aula_id: str

class CheckoutSchema(BaseModel):
    email: EmailStr
    nome: str = ""

class PaymentIntentResponse(BaseModel):
    client_secret: str

# ── Auth guard ────────────────────────────────
seguranca = HTTPBearer()

def usuario_autenticado(credentials: HTTPAuthorizationCredentials = Depends(seguranca)):
    email = verificar_token(credentials.credentials)
    if not email:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado. Faça login novamente.")
    return email

# ── ROTAS PÚBLICAS ────────────────────────────

@app.get("/")
def raiz():
    return {"status": "UniDatas API online"}

@app.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, dados: LoginSchema):
    email = dados.email.lower().strip()
    usuario = buscar_usuario(email)
    erro_generico = HTTPException(status_code=401, detail="E-mail ou senha incorretos")

    if not usuario:
        raise erro_generico

    if usuario.get("ativo") != "sim":
        raise HTTPException(status_code=403, detail="Conta desativada. Entre em contato com o suporte.")

    if not verificar_senha(dados.password, usuario["senha_hash"]):
        raise erro_generico

    token = gerar_token(email)
    return {
        "token": token,
        "email": email,
        "nome": usuario.get("nome", "")
    }

@app.post("/recuperar-senha")
@limiter.limit("3/minute")
async def recuperar_senha(request: Request, dados: RecuperacaoSchema):
    email = dados.email.lower().strip()
    usuario = buscar_usuario(email)
    if usuario:
        nova_senha = gerar_senha_temporaria()
        novo_hash = hash_senha(nova_senha)
        atualizar_senha(email, novo_hash)
        enviar_recuperacao_senha(email, nova_senha)
    return {"message": "Se este e-mail estiver cadastrado, você receberá as instruções em breve."}

@app.post("/checkout")
@limiter.limit("10/minute")
async def criar_checkout(request: Request, dados: CheckoutSchema):
    try:
        params = {
            "success_url": dados.success_url,
            "cancel_url": dados.cancel_url,
            "mode": "payment",
            "locale": "pt-BR",
        }
        if STRIPE_PRICE_ID:
            params["line_items"] = [{"price": STRIPE_PRICE_ID, "quantity": 1}]
        else:
            raise HTTPException(status_code=500, detail="STRIPE_PRICE_ID não configurado")

        session = stripe.checkout.Session.create(**params)
        return {"url": session.url}
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=500, detail=f"Erro ao criar sessão: {e.user_message or str(e)}")

# ── ROTAS PROTEGIDAS (exigem token) ───────────

@app.get("/me")
@limiter.limit("30/minute")
async def meu_perfil(request: Request, email: str = Depends(usuario_autenticado)):
    usuario = buscar_usuario(email)
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    criado_em = usuario.get("criado_em", "")
    from datetime import datetime
    download_liberado = True
    dias_restantes = 0
    if criado_em:
        try:
            data_criacao = datetime.strptime(criado_em, "%Y-%m-%d %H:%M:%S")
            delta = datetime.utcnow() - data_criacao
            if delta.days < 7:
                download_liberado = False
                dias_restantes = 7 - delta.days
        except ValueError:
            pass
    return {
        "email": usuario["email"],
        "nome": usuario["nome"],
        "criado_em": criado_em,
        "download_liberado": download_liberado,
        "dias_restantes": dias_restantes
    }

@app.post("/trocar-senha")
@limiter.limit("5/minute")
async def trocar_senha(
    request: Request,
    dados: TrocarSenhaSchema,
    email: str = Depends(usuario_autenticado)
):
    if len(dados.nova_senha) < 8:
        raise HTTPException(status_code=400, detail="A nova senha deve ter pelo menos 8 caracteres")
    if not any(c.isupper() for c in dados.nova_senha):
        raise HTTPException(status_code=400, detail="A senha deve conter pelo menos uma letra maiúscula")
    if not any(c.islower() for c in dados.nova_senha):
        raise HTTPException(status_code=400, detail="A senha deve conter pelo menos uma letra minúscula")
    if not any(c.isdigit() for c in dados.nova_senha):
        raise HTTPException(status_code=400, detail="A senha deve conter pelo menos um número")
    usuario = buscar_usuario(email)
    if not usuario or not verificar_senha(dados.senha_atual, usuario["senha_hash"]):
        raise HTTPException(status_code=401, detail="Senha atual incorreta")
    novo_hash = hash_senha(dados.nova_senha)
    sucesso, msg = atualizar_senha(email, novo_hash)
    if not sucesso:
        raise HTTPException(status_code=500, detail="Erro ao atualizar senha")
    return {"message": "Senha atualizada com sucesso"}

@app.get("/aulas")
@limiter.limit("30/minute")
async def get_aulas(request: Request, email: str = Depends(usuario_autenticado)):
    aulas = listar_aulas()
    progresso = buscar_progresso(email)
    for aula in aulas:
        aula["assistido"] = aula["id"] in progresso
    return {
        "aulas": aulas,
        "total": len(aulas),
        "assistidas": len(progresso)
    }

@app.get("/aula/{aula_id}")
@limiter.limit("30/minute")
async def get_aula(request: Request, aula_id: str, email: str = Depends(usuario_autenticado)):
    link = buscar_link_aula(aula_id)
    if not link:
        raise HTTPException(status_code=404, detail="Aula não encontrada")
    descricao = buscar_descricao_aula(aula_id)
    return {"link_video": link, "descricao": descricao}

@app.post("/progresso")
@limiter.limit("20/minute")
async def registrar_progresso(
    request: Request,
    dados: ProgressoSchema,
    email: str = Depends(usuario_autenticado)
):
    sucesso, msg = salvar_progresso(email, dados.aula_id)
    if not sucesso:
        raise HTTPException(status_code=500, detail="Erro ao salvar progresso")
    return {"message": "Progresso salvo"}

@app.get("/progresso")
@limiter.limit("30/minute")
async def get_progresso(request: Request, email: str = Depends(usuario_autenticado)):
    aulas = listar_aulas()
    assistidas = buscar_progresso(email)
    total = len(aulas)
    concluidas = len(assistidas)
    percentual = round((concluidas / total) * 100) if total > 0 else 0
    return {
        "total_aulas": total,
        "assistidas": concluidas,
        "percentual": percentual,
        "aulas_assistidas": assistidas
    }
