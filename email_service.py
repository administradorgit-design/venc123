import resend
from dotenv import load_dotenv
import os

load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")
EMAIL_REMETENTE = os.getenv("EMAIL_REMETENTE", "noreply@unidatas.com")

def enviar_boas_vindas(email_aluno: str, senha_temporaria: str):
    """Envia email com credenciais de acesso para o novo aluno."""
    try:
        resend.Emails.send({
            "from": EMAIL_REMETENTE,
            "to": email_aluno,
            "subject": "Bem-vindo à UniDatas — Seus dados de acesso",
            "html": f"""
            <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;">
                <h2 style="color: #1a1a1a;">Bem-vindo à UniDatas!</h2>
                <p>Seu acesso foi liberado. Use as credenciais abaixo para entrar na plataforma:</p>
                <div style="background: #f5f5f5; padding: 20px; border-radius: 6px; margin: 20px 0;">
                    <p><strong>E-mail:</strong> {email_aluno}</p>
                    <p><strong>Senha:</strong> {senha_temporaria}</p>
                </div>
                <p>Acesse agora: <a href="https://unidatas.com/login">unidatas.com/login</a></p>
                <p style="color: #888; font-size: 12px; margin-top: 30px;">
                    Recomendamos trocar sua senha após o primeiro acesso.
                </p>
            </div>
            """
        })
        return True
    except Exception as e:
        print(f"Erro ao enviar email: {e}")
        return False

def enviar_recuperacao_senha(email_aluno: str, nova_senha: str):
    """Envia email com nova senha após solicitação de recuperação."""
    try:
        resend.Emails.send({
            "from": EMAIL_REMETENTE,
            "to": email_aluno,
            "subject": "UniDatas — Sua nova senha",
            "html": f"""
            <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;">
                <h2 style="color: #1a1a1a;">Redefinição de senha</h2>
                <p>Sua nova senha de acesso é:</p>
                <div style="background: #f5f5f5; padding: 20px; border-radius: 6px; margin: 20px 0;">
                    <p><strong>Senha:</strong> {nova_senha}</p>
                </div>
                <p>Acesse: <a href="https://unidatas.com/login">unidatas.com/login</a></p>
                <p style="color: #888; font-size: 12px; margin-top: 30px;">
                    Se não foi você que solicitou, ignore este email.
                </p>
            </div>
            """
        })
        return True
    except Exception as e:
        print(f"Erro ao enviar email de recuperação: {e}")
        return False

        #venv\Scripts\activate
        #uvicorn main:app --reload --port 8000
