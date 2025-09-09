from flask import Flask, render_template, request, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib, base64

app = Flask(__name__)

# Usuário e senha do login
USUARIO = "admin"
SENHA = "123456"

# --- Criptografia ---
def gerar_chave(senha):
    return hashlib.sha256(senha.encode()).digest()

def criptografar_mensagem(mensagem, senha):
    chave = gerar_chave(senha)
    cipher = AES.new(chave, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(mensagem.encode(), AES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes).decode()

def descriptografar_mensagem(mensagem_cripto, senha):
    try:
        chave = gerar_chave(senha)
        mensagem_bytes = base64.b64decode(mensagem_cripto)
        iv = mensagem_bytes[:16]
        ct = mensagem_bytes[16:]
        cipher = AES.new(chave, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode()
    except:
        return "Senha ou mensagem incorreta!"

# --- Rotas ---
@app.route("/", methods=["GET", "POST"])
def login():
    erro = ""
    if request.method == "POST":
        usuario = request.form.get("usuario")
        senha = request.form.get("senha")
        if usuario == USUARIO and senha == SENHA:
            return redirect(url_for("mensagens"))
        else:
            erro = "Usuário ou senha incorretos!"
    return render_template("login.html", erro=erro)

@app.route("/mensagens")
def mensagens():
    return render_template("mensagens.html")

@app.route("/criptografar", methods=["POST"])
def criptografar():
    msg = request.form.get("mensagem")
    senha = request.form.get("senha")
    resultado = criptografar_mensagem(msg, senha)
    return {"resultado": resultado}

@app.route("/descriptografar", methods=["POST"])
def descriptografar():
    msg = request.form.get("mensagem")
    senha = request.form.get("senha")
    resultado = descriptografar_mensagem(msg, senha)
    return {"resultado": resultado}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
