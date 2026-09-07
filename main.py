from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
import bcrypt
import sqlite3

# Configurações de Segurança
SECRET_KEY = "chave_super_secreta_da_bateria_universitaria"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI(title="Bateria Universitaria - Inventario e Compras")

# Servir pasta de arquivos estaticos
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def ler_index():
    return FileResponse("static/index.html")

# --- FUNÇÕES DE SEGURANÇA COM BCRYPT NATIVO ---
def verificar_senha(senha_pura: str, senha_hash: str) -> bool:
    senha_bytes = senha_pura.encode('utf-8')
    # Trunca se passar do limite nativo do bcrypt (72 bytes)
    if len(senha_bytes) > 72:
        senha_bytes = senha_bytes[:72]
    return bcrypt.checkpw(senha_bytes, senha_hash.encode('utf-8'))

def gerar_hash_senha(senha_pura: str) -> str:
    senha_bytes = senha_pura.encode('utf-8')
    if len(senha_bytes) > 72:
        senha_bytes = senha_bytes[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(senha_bytes, salt).decode('utf-8')

def criar_token_acesso(dados: dict, expires_delta: Optional[timedelta] = None):
    para_codificar = dados.copy()
    expirar = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    para_codificar.update({"exp": expirar})
    return jwt.encode(para_codificar, SECRET_KEY, algorithm=ALGORITHM)

# Função de Conexão com SQLite
def get_db():
    conn = sqlite3.connect("bateria.db")
    conn.row_factory = sqlite3.Row
    return conn

# --- INICIALIZAÇÃO DO BANCO ---
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Tabela 1: Usuarios (Login)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        senha_hash TEXT NOT NULL
    )
    """)
    
    # Tabela 2: Inventario
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS inventario (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        categoria TEXT NOT NULL,
        quantidade INTEGER NOT NULL,
        estado TEXT NOT NULL
    )
    """)
    
    # Tabela 3: Lista de Compras
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS compras (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item TEXT NOT NULL,
        quantidade INTEGER NOT NULL,
        status TEXT DEFAULT 'Pendente'
    )
    """)
    
    # Cria o usuario padrao 'admin' com a senha 'bateria123' se nao existir
    cursor.execute("SELECT * FROM usuarios WHERE username = 'admin'")
    if not cursor.fetchone():
        senha_criptografada = gerar_hash_senha("bateria123")
        cursor.execute(
            "INSERT INTO usuarios (username, senha_hash) VALUES (?, ?)",
            ("admin", senha_criptografada)
        )
        print("[SISTEMA] Usuario 'admin' criado com a senha 'bateria123'")

    conn.commit()
    conn.close()

init_db()

# Dependência para Proteger Rotas
def obter_usuario_atual(token: str = Depends(oauth2_scheme)):
    credenciais_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais invalidas ou token expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credenciais_exception
    except JWTError:
        raise credenciais_exception
        
    return username

# --- MODELOS ---
class ItemInventario(BaseModel):
    nome: str
    categoria: str
    quantidade: int
    estado: str

class ItemCompra(BaseModel):
    item: str
    quantidade: int

# --- ROTA DE LOGIN ---
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
    cursor = conn.cursor()
    usuario = cursor.execute(
        "SELECT * FROM usuarios WHERE username = ?", (form_data.username,)
    ).fetchone()
    conn.close()

    if not usuario or not verificar_senha(form_data.password, usuario["senha_hash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario ou senha incorretos"
        )

    tempo_expiracao = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = criar_token_acesso(
        dados={"sub": usuario["username"]}, expires_delta=tempo_expiracao
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- ROTAS PROTEGIDAS ---

@app.get("/inventario")
def listar_inventario(usuario: str = Depends(obter_usuario_atual)):
    conn = get_db()
    cursor = conn.cursor()
    itens = cursor.execute("SELECT * FROM inventario").fetchall()
    conn.close()
    return [dict(item) for item in itens]

@app.get("/compras")
def listar_compras(usuario: str = Depends(obter_usuario_atual)):
    conn = get_db()
    cursor = conn.cursor()
    compras = cursor.execute("SELECT * FROM compras").fetchall()
    conn.close()
    return [dict(c) for c in compras]

@app.post("/inventario")
def criar_item_inventario(item: ItemInventario, usuario: str = Depends(obter_usuario_atual)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO inventario (nome, categoria, quantidade, estado) VALUES (?, ?, ?, ?)",
        (item.nome, item.categoria, item.quantidade, item.estado)
    )
    conn.commit()
    item_id = cursor.lastrowid
    conn.close()
    return {"id": item_id, "mensagem": f"Item adicionado por {usuario}"}

@app.delete("/inventario/{item_id}")
def deletar_item_inventario(item_id: int, usuario: str = Depends(obter_usuario_atual)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM inventario WHERE id = ?", (item_id,))
    alterados = cursor.rowcount
    conn.commit()
    conn.close()
    if alterados == 0:
        raise HTTPException(status_code=404, detail="Item nao encontrado")
    return {"mensagem": "Item removido com sucesso!"}

@app.post("/compras")
def criar_item_compra(compra: ItemCompra, usuario: str = Depends(obter_usuario_atual)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO compras (item, quantidade) VALUES (?, ?)",
        (compra.item, compra.quantidade)
    )
    conn.commit()
    compra_id = cursor.lastrowid
    conn.close()
    return {"id": compra_id, "mensagem": "Item adicionado a lista de compras!"}