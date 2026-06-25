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
from webhook_kiwify import router as kiwify_router
import os

load_dotenv()

# ── Rate limiter ──────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="UniDatas API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ──────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://unidatas.com",
        "https://www.unidatas.com",
        "http://localhost:5500",
        "http://127.0.0.1:5500"
    ],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ── Webhook Hotmart ───────────────────────────
app.include_router(webhook_router)
app.include_router(kiwify_router)

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
    # Resposta igual mesmo se email não existir — evita enumeração de emails
    if usuario:
        nova_senha = gerar_senha_temporaria()
        novo_hash = hash_senha(nova_senha)
        atualizar_senha(email, novo_hash)
        enviar_recuperacao_senha(email, nova_senha)
    return {"message": "Se este e-mail estiver cadastrado, você receberá as instruções em breve."}

# ── ROTAS PROTEGIDAS (exigem token) ───────────

@app.get("/me")
async def meu_perfil(email: str = Depends(usuario_autenticado)):
    """Dados básicos do aluno logado."""
    usuario = buscar_usuario(email)
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return {
        "email": usuario["email"],
        "nome": usuario["nome"]
    }

@app.post("/trocar-senha")
@limiter.limit("5/minute")
async def trocar_senha(
    request: Request,
    dados: TrocarSenhaSchema,
    email: str = Depends(usuario_autenticado)
):
    if len(dados.nova_senha) < 6:
        raise HTTPException(status_code=400, detail="A nova senha deve ter pelo menos 6 caracteres")
    usuario = buscar_usuario(email)
    if not usuario or not verificar_senha(dados.senha_atual, usuario["senha_hash"]):
        raise HTTPException(status_code=401, detail="Senha atual incorreta")
    novo_hash = hash_senha(dados.nova_senha)
    sucesso, msg = atualizar_senha(email, novo_hash)
    if not sucesso:
        raise HTTPException(status_code=500, detail="Erro ao atualizar senha")
    return {"message": "Senha atualizada com sucesso"}

@app.get("/aulas")
async def get_aulas(email: str = Depends(usuario_autenticado)):
    """
    Retorna a lista de aulas do curso.
    O link do vídeo NÃO vem aqui — só vem em /aula/{id}.
    """
    aulas = listar_aulas()
    progresso = buscar_progresso(email)
    # Adiciona flag de assistido em cada aula
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
    """
    Entrega o link do vídeo para uma aula específica.
    Só funciona com token válido.
    """
    link = buscar_link_aula(aula_id)
    if not link:
        raise HTTPException(status_code=404, detail="Aula não encontrada")
    descricao = buscar_descricao_aula(aula_id)
    return {"link_video": link, "descricao": descricao}

@app.post("/progresso")
async def registrar_progresso(
    dados: ProgressoSchema,
    email: str = Depends(usuario_autenticado)
):
    """Marca uma aula como assistida."""
    sucesso, msg = salvar_progresso(email, dados.aula_id)
    if not sucesso:
        raise HTTPException(status_code=500, detail="Erro ao salvar progresso")
    return {"message": "Progresso salvo"}

@app.get("/progresso")
async def get_progresso(email: str = Depends(usuario_autenticado)):
    """Retorna o progresso completo do aluno."""
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