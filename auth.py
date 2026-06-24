import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITMO = "HS256"
JWT_EXPIRACAO_HORAS = int(os.getenv("JWT_EXPIRACAO_HORAS", 8))

def hash_senha(senha: str) -> str:
    """Gera hash seguro da senha com bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(senha.encode("utf-8"), salt).decode("utf-8")

def verificar_senha(senha: str, senha_hash: str) -> bool:
    """Verifica se a senha bate com o hash."""
    return bcrypt.checkpw(senha.encode("utf-8"), senha_hash.encode("utf-8"))

def gerar_token(email: str) -> str:
    """Gera JWT com expiração."""
    payload = {
        "sub": email,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRACAO_HORAS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITMO)

def verificar_token(token: str) -> str | None:
    """Valida o JWT e retorna o email ou None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITMO])
        return payload.get("sub")
    except JWTError:
        return None

def gerar_senha_temporaria() -> str:
    """Gera senha aleatória de 10 caracteres para novos alunos."""
    import secrets
    import string
    caracteres = string.ascii_letters + string.digits
    return ''.join(secrets.choice(caracteres) for _ in range(10))