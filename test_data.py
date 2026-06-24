# ── Dados de teste para desenvolvimento local ────────────────────
# Simula os usuários do Google Sheets durante desenvolvimento

from auth import hash_senha

# Dados de teste em memória
USUARIOS_TESTE = {
    "joao@unidatas.com": {
        "email": "joao@unidatas.com",
        "nome": "João Silva",
        "senha_hash": hash_senha("senha123"),
        "ativo": "sim"
    },
    "maria@unidatas.com": {
        "email": "maria@unidatas.com",
        "nome": "Maria Santos",
        "senha_hash": hash_senha("senha456"),
        "ativo": "sim"
    },
    "admin@unidatas.com": {
        "email": "admin@unidatas.com",
        "nome": "Admin",
        "senha_hash": hash_senha("admin123"),
        "ativo": "sim"
    }
}

def buscar_usuario_teste(email: str):
    """Busca usuário nos dados de teste."""
    return USUARIOS_TESTE.get(email.lower())

def atualizar_senha_teste(email: str, novo_hash: str):
    """Atualiza senha nos dados de teste."""
    if email.lower() in USUARIOS_TESTE:
        USUARIOS_TESTE[email.lower()]["senha_hash"] = novo_hash
        return True, "Senha atualizada"
    return False, "Usuário não encontrado"

def criar_usuario_teste(email: str, nome: str, senha: str):
    """Cria novo usuário nos dados de teste."""
    email = email.lower()
    if email in USUARIOS_TESTE:
        return False, "Email já existe"
    
    USUARIOS_TESTE[email] = {
        "email": email,
        "nome": nome,
        "senha_hash": hash_senha(senha),
        "ativo": "sim"
    }
    return True, "Usuário criado"
