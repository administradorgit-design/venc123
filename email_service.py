import resend
from dotenv import load_dotenv
import os

load_dotenv()

resend.api_key = (os.getenv("RESEND_API_KEY") or "").strip()
EMAIL_REMETENTE = (os.getenv("EMAIL_REMETENTE") or "noreply@unidatas.com.br").strip()

def enviar_boas_vindas(email_aluno: str, senha_temporaria: str):
    """Envia email com credenciais de acesso para o novo aluno."""
    try:
        resend.Emails.send({
            "from": EMAIL_REMETENTE,
            "to": email_aluno,
            "subject": "OddsBot Academy — Seus dados de acesso",
            "html": f"""
            <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;">

                <div style="text-align: center; margin-bottom: 28px;">
                    <h1 style="font-size: 22px; font-weight: 900; letter-spacing: 3px; color: #1a1a1a;">UNIDATAS</h1>
                </div>

                <h2 style="color: #1a1a1a; font-size: 18px;">Bem-vindo ao OddsBot Academy!</h2>
                <p style="color: #555; margin-top: 8px;">Seu acesso foi liberado. Use as credenciais abaixo para entrar na plataforma:</p>

                <div style="background: #f5f5f5; border: 1px solid #e0e0e0; padding: 20px; border-radius: 6px; margin: 24px 0;">
                    <p style="margin: 0 0 10px;"><strong>E-mail:</strong> {email_aluno}</p>
                    <p style="margin: 0;"><strong>Senha:</strong> {senha_temporaria}</p>
                </div>

                <div style="text-align: center; margin: 28px 0;">
                    <a href="https://unidatas.com.br/portal-login.html"
                       style="background: #1a1a1a; color: #fff; padding: 14px 32px; border-radius: 4px; text-decoration: none; font-weight: 700; font-size: 14px; letter-spacing: 1px;">
                        ACESSAR AGORA
                    </a>
                </div>

                <p style="color: #888; font-size: 12px; margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 16px;">
                    Recomendamos trocar sua senha após o primeiro acesso.<br>
                    Se você não realizou essa compra, ignore este email.
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
            "subject": "OddsBot Academy — Sua nova senha",
            "html": f"""
            <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;">

                <div style="text-align: center; margin-bottom: 28px;">
                    <h1 style="font-size: 22px; font-weight: 900; letter-spacing: 3px; color: #1a1a1a;">UNIDATAS</h1>
                </div>

                <h2 style="color: #1a1a1a; font-size: 18px;">Redefinição de senha</h2>
                <p style="color: #555; margin-top: 8px;">Sua nova senha de acesso é:</p>

                <div style="background: #f5f5f5; border: 1px solid #e0e0e0; padding: 20px; border-radius: 6px; margin: 24px 0;">
                    <p style="margin: 0;"><strong>Senha:</strong> {nova_senha}</p>
                </div>

                <div style="text-align: center; margin: 28px 0;">
                    <a href="https://unidatas.com.br/portal-login.html"
                       style="background: #1a1a1a; color: #fff; padding: 14px 32px; border-radius: 4px; text-decoration: none; font-weight: 700; font-size: 14px; letter-spacing: 1px;">
                        ACESSAR AGORA
                    </a>
                </div>

                <p style="color: #888; font-size: 12px; margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 16px;">
                    Se não foi você que solicitou a redefinição, ignore este email.
                </p>

            </div>
            """
        })
        return True
    except Exception as e:
        print(f"Erro ao enviar email de recuperação: {e}")
        return False