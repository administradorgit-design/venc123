import gspread
from google.oauth2.service_account import Credentials
from dotenv import load_dotenv
import os
import json

load_dotenv()

ESCOPOS = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive"
]

def conectar_planilha():
    cred_json = os.getenv("GOOGLE_CREDENTIALS_JSON")
    if not cred_json:
        raise RuntimeError("GOOGLE_CREDENTIALS_JSON não está definido")

    if os.path.isfile(cred_json):
        creds = Credentials.from_service_account_file(
            cred_json,
            scopes=ESCOPOS
        )
    else:
        try:
            service_account_info = json.loads(cred_json)
        except Exception as exc:
            raise RuntimeError(
                "GOOGLE_CREDENTIALS_JSON deve ser um caminho de arquivo válido ou um JSON de credenciais do service account"
            ) from exc
        creds = Credentials.from_service_account_info(
            service_account_info,
            scopes=ESCOPOS
        )

    cliente = gspread.authorize(creds)
    return cliente.open_by_key(os.getenv("PLANILHA_ID"))

def aba_usuarios():
    return conectar_planilha().worksheet("usuarios")

def aba_aulas():
    return conectar_planilha().worksheet("aulas")

# Cache simples em memória para evitar erro 429
_cache_aulas = None
_cache_tempo = 0

def listar_aulas_cache():
    """Retorna aulas do cache ou busca no Sheets se expirado."""
    import time
    global _cache_aulas, _cache_tempo
    # Cache válido por 5 minutos
    if _cache_aulas and (time.time() - _cache_tempo) < 300:
        return _cache_aulas
    try:
        aba = aba_aulas()
        _cache_aulas = aba.get_all_records()
        _cache_tempo = time.time()
        return _cache_aulas
    except Exception as e:
        print(f"Erro ao buscar aulas: {e}")
        return _cache_aulas or []

def aba_progresso():
    return conectar_planilha().worksheet("progresso")

# ── USUÁRIOS ──────────────────────────────────

def buscar_usuario(email: str):
    try:
        aba = aba_usuarios()
        emails = aba.col_values(1)
        if email not in emails:
            return None
        linha = emails.index(email) + 1
        dados = aba.row_values(linha)
        return {
            "email": dados[0],
            "senha_hash": dados[1],
            "nome": dados[2] if len(dados) > 2 else "",
            "ativo": dados[3] if len(dados) > 3 else "sim"
        }
    except Exception as e:
        print(f"Erro ao buscar usuário: {e}")
        return None

def criar_usuario(email: str, senha_hash: str, nome: str = ""):
    try:
        if buscar_usuario(email):
            return False, "Usuário já existe"
        aba_usuarios().append_row([email, senha_hash, nome, "sim"])
        return True, "Usuário criado"
    except Exception as e:
        print(f"Erro ao criar usuário: {e}")
        return False, str(e)

def atualizar_senha(email: str, nova_senha_hash: str):
    try:
        aba = aba_usuarios()
        emails = aba.col_values(1)
        if email not in emails:
            return False, "Usuário não encontrado"
        linha = emails.index(email) + 1
        aba.update_cell(linha, 2, nova_senha_hash)
        return True, "Senha atualizada"
    except Exception as e:
        print(f"Erro ao atualizar senha: {e}")
        return False, str(e)

# ── AULAS ─────────────────────────────────────

def listar_aulas():
    """Retorna todas as aulas SEM o link do vídeo."""
    try:
        registros = listar_aulas_cache()
        return [
            {
                "id": str(a.get("id", "")),
                "ordem": a.get("ordem", ""),
                "titulo": a.get("titulo", ""),
                "modulo": a.get("modulo", ""),
                "duracao": a.get("duracao", ""),
            }
            for a in registros
        ]
    except Exception as e:
        print(f"Erro ao listar aulas: {e}")
        return []

def buscar_descricao_aula(aula_id: str):
    """Retorna a descrição de uma aula específica."""
    try:
        registros = listar_aulas_cache()
        for aula in registros:
            if str(aula.get("id")) == aula_id:
                return aula.get("descricao", "")
        return ""
    except Exception as e:
        print(f"Erro ao buscar descrição: {e}")
        return ""

def buscar_link_aula(aula_id: str):
    """Retorna o link do vídeo de uma aula — só entregue após validação do token."""
    try:
        registros = listar_aulas_cache()
        for aula in registros:
            if str(aula.get("id")) == aula_id:
                # Tenta várias chaves possíveis para o link do vídeo (fallbacks comuns)
                for chave in ("link_video", "link", "video", "video_url", "url", "embed"):
                    valor = aula.get(chave)
                    if valor and str(valor).strip() != "":
                        return str(valor).strip()
                return None
        return None
    except Exception as e:
        print(f"Erro ao buscar link da aula: {e}")
        return None

# ── PROGRESSO ─────────────────────────────────

def buscar_progresso(email: str):
    """Retorna lista de IDs de aulas assistidas pelo aluno."""
    try:
        aba = aba_progresso()
        registros = aba.get_all_records()
        return [
            str(r["aula_id"])
            for r in registros
            if r.get("email") == email and str(r.get("assistido")) == "sim"
        ]
    except Exception as e:
        print(f"Erro ao buscar progresso: {e}")
        return []

def salvar_progresso(email: str, aula_id: str):
    """Marca uma aula como assistida. Evita duplicatas."""
    try:
        aba = aba_progresso()
        registros = aba.get_all_records()
        for r in registros:
            if r.get("email") == email and str(r.get("aula_id")) == aula_id:
                return True, "Já registrado"
        from datetime import datetime
        aba.append_row([email, aula_id, "sim", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")])
        return True, "Progresso salvo"
    except Exception as e:
        print(f"Erro ao salvar progresso: {e}")
        return False, str(e)