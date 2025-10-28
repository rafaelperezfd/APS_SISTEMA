import json, os, base64, secrets, hashlib, pathlib, datetime
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# Pastas/arquivos
APP_DIR = pathlib.Path(__file__).resolve().parent
ARQ_USUARIOS     = APP_DIR / "users.json"        # mantém nome físico para compatibilidade
ARQ_SUBSTANCIAS  = APP_DIR / "substances.json"   # mantém nome físico para compatibilidade
ARQ_AMOSTRAS     = APP_DIR / "samples.json"      # mantém nome físico para compatibilidade
ARQ_LOG          = APP_DIR / "audit_log.jsonl"   # mantém nome físico para compatibilidade

# Parâmetros scrypt
SCRYPT_N, SCRYPT_R, SCRYPT_P, TAM_CHAVE = 16384, 8, 1, 64

def agora_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")

def gerar_hash_scrypt(senha: str, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    sal = secrets.token_bytes(16)
    dk = hashlib.scrypt(senha.encode("utf-8"), salt=sal, n=n, r=r, p=p, dklen=TAM_CHAVE)
    return {
        "sal_b64": base64.b64encode(sal).decode(),
        "hash_b64": base64.b64encode(dk).decode(),
        "parametros": {"n": n, "r": r, "p": p}
    }

def verificar_hash_scrypt(senha: str, obj_hash: dict) -> bool:
    sal = base64.b64decode(obj_hash["sal_b64"])
    esperado = base64.b64decode(obj_hash["hash_b64"])
    n = int(obj_hash["parametros"]["n"]); r = int(obj_hash["parametros"]["r"]); p = int(obj_hash["parametros"]["p"])
    dk = hashlib.scrypt(senha.encode("utf-8"), salt=sal, n=n, r=r, p=p, dklen=len(esperado))
    return secrets.compare_digest(dk, esperado)

def registrar_evento(path: pathlib.Path, evento: dict):
    linha = json.dumps(evento, ensure_ascii=False)
    with open(path, "a", encoding="utf-8") as f:
        f.write(linha + "\n")

def escrita_atomica(path: pathlib.Path, dados: dict):
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(dados, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def carregar_json_seguro(path: pathlib.Path, obj_padrao: dict) -> dict:
    try:
        if not path.exists() or path.stat().st_size == 0:
            escrita_atomica(path, obj_padrao)
            return obj_padrao
        with open(path, "r", encoding="utf-8") as f:
            bruto = f.read()
        if not bruto.strip():
            escrita_atomica(path, obj_padrao)
            return obj_padrao
        dados = json.loads(bruto)
        if not isinstance(dados, dict):
            raise json.JSONDecodeError("Raiz deve ser objeto", bruto, 0)
        return dados
    except json.JSONDecodeError:
        escrita_atomica(path, obj_padrao)
        return obj_padrao

def garantir_arquivos_dados():
    if not ARQ_USUARIOS.exists():
        escrita_atomica(ARQ_USUARIOS, {"versao": 1, "usuarios": []})
    if not ARQ_SUBSTANCIAS.exists():
        escrita_atomica(ARQ_SUBSTANCIAS, {"versao": 1, "substancias": []})
    if not ARQ_AMOSTRAS.exists():
        escrita_atomica(ARQ_AMOSTRAS, {"versao": 1, "amostras": []})
    if not ARQ_LOG.exists():
        ARQ_LOG.touch()

def salvar_json(path: pathlib.Path, dados: dict):
    escrita_atomica(path, dados)

# Normalização/compatibilidade para usuários
def _normalizar_lista_usuarios(dados: dict):
    # aceita "usuarios" (pt) ou "users" (en)
    lista = []
    if "usuarios" in dados and isinstance(dados["usuarios"], list):
        lista = dados["usuarios"]
    elif "users" in dados and isinstance(dados["users"], list):
        lista = dados["users"]
    # mapear chaves para pt-BR
    norm = []
    for u in lista:
        norm.append({
            "cracha": u.get("cracha", u.get("badge_id", "")),
            "nome": u.get("nome", u.get("name", "")),
            "papel": u.get("papel", u.get("role", "user")),
            "ativo": bool(u.get("ativo", u.get("active", False))),
            "senha_hash": u.get("senha_hash", u.get("password", None)),
            "senha_plana": u.get("senha_plana", u.get("password_plain", None)),
        })
    return norm

def carregar_usuarios():
    dados = carregar_json_seguro(ARQ_USUARIOS, {"versao": 1, "usuarios": []})
    return _normalizar_lista_usuarios(dados)

def salvar_usuarios(usuarios_pt: list):
    # salva em português
    salvar_json(ARQ_USUARIOS, {"versao": 1, "usuarios": usuarios_pt})

def buscar_usuario(cracha: str):
    usuarios = carregar_usuarios()
    for u in usuarios:
        if u.get("cracha") == cracha:
            return u, usuarios
    return None, usuarios

# Autenticação: aceita senha_hash (scrypt) e senha_plana
def verificar_credenciais(senha_digitada: str, usuario: dict) -> bool:
    if isinstance(usuario.get("senha_hash"), dict) and "hash_b64" in usuario["senha_hash"]:
        return verificar_hash_scrypt(senha_digitada, usuario["senha_hash"])
    if "senha_plana" in usuario and usuario["senha_plana"] is not None:
        return secrets.compare_digest(senha_digitada, usuario["senha_plana"])
    return False

class TelaLogin(ttk.Frame):
    def __init__(self, master, ao_autenticar):
        super().__init__(master, padding=20)
        self.ao_autenticar = ao_autenticar
        self.var_cracha = tk.StringVar()
        self.var_senha  = tk.StringVar()

        ttk.Label(self, text="Login", font=("-size", 16)).pack(pady=(0,12))
        frm = ttk.Frame(self); frm.pack(fill=X)

        ttk.Label(frm, text="Crachá:").grid(row=0, column=0, sticky=W, pady=6)
        ttk.Entry(frm, textvariable=self.var_cracha, width=32).grid(row=0, column=1, sticky=EW, padx=6)

        ttk.Label(frm, text="Senha:").grid(row=1, column=0, sticky=W, pady=6)
        ttk.Entry(frm, textvariable=self.var_senha, show="•", width=32).grid(row=1, column=1, sticky=EW, padx=6)

        botoes = ttk.Frame(self); botoes.pack(pady=12)
        ttk.Button(botoes, text="Entrar", bootstyle=SUCCESS, command=self._entrar).pack(side=LEFT, padx=6)
        ttk.Button(botoes, text="Fechar", bootstyle=DANGER, command=self.quit).pack(side=LEFT, padx=6)

        frm.columnconfigure(1, weight=1)
        self.pack(fill=BOTH, expand=YES)

    def _entrar(self):
        cracha = self.var_cracha.get().strip()
        senha  = self.var_senha.get()
        usuario, _todos = buscar_usuario(cracha)
        if not usuario or not usuario.get("ativo", False):
            messagebox.showerror("Acesso negado", "Crachá não encontrado ou inativo.")
            registrar_evento(ARQ_LOG, {"ts": agora_iso(), "tipo":"login", "cracha": cracha, "resultado":"negado"})
            return
        if not verificar_credenciais(senha, usuario):
            messagebox.showerror("Acesso negado", "Senha incorreta.")
            registrar_evento(ARQ_LOG, {"ts": agora_iso(), "tipo":"login", "cracha": cracha, "resultado":"negado"})
            return
        registrar_evento(ARQ_LOG, {"ts": agora_iso(), "tipo":"login", "cracha": cracha, "resultado":"permitido"})
        self.ao_autenticar(usuario)

class TelaUsuarios(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.var_cracha = tk.StringVar(); self.var_nome = tk.StringVar()
        self.var_papel  = tk.StringVar(value="user")
        self.var_senha  = tk.StringVar(); self.var_ativo = tk.BooleanVar(value=True)

        frm = ttk.Labelframe(self, text="Usuários", padding=12); frm.pack(fill=X)
        ttk.Label(frm, text="Crachá:").grid(row=0, column=0, sticky=W, pady=4)
        ttk.Entry(frm, textvariable=self.var_cracha).grid(row=0, column=1, sticky=EW, padx=6)
        ttk.Label(frm, text="Nome:").grid(row=1, column=0, sticky=W, pady=4)
        ttk.Entry(frm, textvariable=self.var_nome).grid(row=1, column=1, sticky=EW, padx=6)
        ttk.Label(frm, text="Papel:").grid(row=2, column=0, sticky=W, pady=4)
        ttk.Combobox(frm, textvariable=self.var_papel, values=["admin","user"], state="readonly").grid(row=2, column=1, sticky=EW, padx=6)
        ttk.Label(frm, text="Senha (8+):").grid(row=3, column=0, sticky=W, pady=4)
        ttk.Entry(frm, textvariable=self.var_senha, show="•").grid(row=3, column=1, sticky=EW, padx=6)
        ttk.Checkbutton(frm, text="Ativo", variable=self.var_ativo, bootstyle=SUCCESS).grid(row=4, column=1, sticky=W, pady=4)

        botoes = ttk.Frame(frm); botoes.grid(row=5, column=0, columnspan=2, pady=8)
        ttk.Button(botoes, text="Salvar/Atualizar", bootstyle=PRIMARY, command=self._salvar_usuario).pack(side=LEFT, padx=5)
        ttk.Button(botoes, text="Deletar", bootstyle=DANGER, command=self._deletar_usuario).pack(side=LEFT, padx=5)
        ttk.Button(botoes, text="Limpar", bootstyle=SECONDARY, command=self._limpar_form).pack(side=LEFT, padx=5)
        frm.columnconfigure(1, weight=1)

        self.tabela = ttk.Treeview(self, columns=("cracha","nome","papel","ativo"), show="headings", height=10, bootstyle=INFO)
        for c,t in zip(("cracha","nome","papel","ativo"), ("Crachá","Nome","Papel","Ativo")):
            self.tabela.heading(c, text=t); self.tabela.column(c, width=160 if c!="nome" else 240)
        self.tabela.pack(fill=BOTH, expand=YES, pady=8)
        self.tabela.bind("<<TreeviewSelect>>", self._ao_selecionar)
        self._recarregar()

    def _recarregar(self):
        for i in self.tabela.get_children(): self.tabela.delete(i)
        usuarios = carregar_usuarios()
        for u in usuarios:
            self.tabela.insert("", tk.END, values=(u["cracha"], u["nome"], u["papel"], "Sim" if u.get("ativo") else "Não"))

    def _limpar_form(self):
        self.var_cracha.set(""); self.var_nome.set(""); self.var_papel.set("user"); self.var_senha.set(""); self.var_ativo.set(True)

    def _ao_selecionar(self, _):
        sel = self.tabela.selection()
        if not sel: return
        cracha, nome, papel, ativo = self.tabela.item(sel[0])["values"]
        self.var_cracha.set(cracha); self.var_nome.set(nome); self.var_papel.set(papel); self.var_ativo.set(ativo=="Sim"); self.var_senha.set("")

    def _salvar_usuario(self):
        cracha = self.var_cracha.get().strip(); nome = self.var_nome.get().strip()
        papel = self.var_papel.get().strip(); senha = self.var_senha.get(); ativo = bool(self.var_ativo.get())
        if not cracha or not nome:
            messagebox.showwarning("Campos", "Informe crachá e nome."); return

        _, todos = buscar_usuario(cracha)
        existente = next((u for u in todos if u["cracha"] == cracha), None)
        if existente:
            existente["nome"] = nome; existente["papel"] = papel; existente["ativo"] = ativo
            if senha:
                if len(senha) < 8: messagebox.showwarning("Senha", "8+ caracteres"); return
                existente["senha_hash"] = gerar_hash_scrypt(senha)
                existente["senha_plana"] = None
        else:
            if len(senha) < 8: messagebox.showwarning("Senha", "8+ caracteres"); return
            todos.append({
                "cracha": cracha,
                "nome": nome,
                "papel": papel,
                "ativo": ativo,
                "senha_hash": gerar_hash_scrypt(senha),
                "senha_plana": None
            })
        salvar_usuarios(todos)
        registrar_evento(ARQ_LOG, {"ts": agora_iso(), "tipo":"usuario_salvar", "cracha": cracha})
        self._recarregar(); self._limpar_form()

    def _deletar_usuario(self):
        cracha = self.var_cracha.get().strip()
        if not cracha: messagebox.showwarning("Seleção","Escolha um usuário."); return
        usuarios = carregar_usuarios()
        usuarios = [u for u in usuarios if u["cracha"] != cracha]
        salvar_usuarios(usuarios)
        registrar_evento(ARQ_LOG, {"ts": agora_iso(), "tipo":"usuario_deletar", "cracha": cracha})
        self._recarregar(); self._limpar_form()

class TelaSubstancias(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        # Variáveis do formulário
        self.var_id     = tk.StringVar()
        self.var_nome   = tk.StringVar()
        self.var_data   = tk.StringVar()
        self.var_status = tk.StringVar()

        topo = ttk.Labelframe(self, text="Cadastro de Substâncias", padding=10)
        topo.pack(fill=X, pady=(0,8))

        ttk.Label(topo, text="ID").grid(row=0, column=0, sticky=W, padx=6, pady=4)
        ttk.Entry(topo, textvariable=self.var_id, width=24).grid(row=0, column=1, sticky=EW, padx=6)

        ttk.Label(topo, text="Nome").grid(row=0, column=2, sticky=W, padx=6, pady=4)
        ttk.Entry(topo, textvariable=self.var_nome, width=36).grid(row=0, column=3, sticky=EW, padx=6)

        ttk.Label(topo, text="Data").grid(row=1, column=0, sticky=W, padx=6, pady=4)
        ttk.Entry(topo, textvariable=self.var_data, width=24).grid(row=1, column=1, sticky=EW, padx=6)

        ttk.Label(topo, text="Status").grid(row=1, column=2, sticky=W, padx=6, pady=4)
        ttk.Entry(topo, textvariable=self.var_status, width=24).grid(row=1, column=3, sticky=EW, padx=6)

        botoes = ttk.Frame(topo); botoes.grid(row=2, column=0, columnspan=4, sticky=W, pady=8)
        ttk.Button(botoes, text="Salvar/Atualizar", bootstyle=PRIMARY, command=self._salvar).pack(side=LEFT, padx=4)
        ttk.Button(botoes, text="Deletar", bootstyle=DANGER, command=self._deletar).pack(side=LEFT, padx=4)
        ttk.Button(botoes, text="Limpar", bootstyle=SECONDARY, command=self._limpar).pack(side=LEFT, padx=4)
        ttk.Button(botoes, text="Recarregar", bootstyle=INFO, command=self._carregar).pack(side=LEFT, padx=4)

        for c in (1,3):
            topo.columnconfigure(c, weight=1)

        self.tabela = ttk.Treeview(self, columns=("id","nome","data","status"), show="headings", bootstyle=INFO, height=12)
        self.tabela.heading("id", text="ID")
        self.tabela.heading("nome", text="Nome")
        self.tabela.heading("data", text="Data")
        self.tabela.heading("status", text="Status")
        self.tabela.column("id", width=140)
        self.tabela.column("nome", width=260)
        self.tabela.column("data", width=160)
        self.tabela.column("status", width=160)
        self.tabela.pack(fill=BOTH, expand=YES)
        self.tabela.bind("<<TreeviewSelect>>", self._selecionar)

        self._carregar()

    def _carregar(self):
        for i in self.tabela.get_children():
            self.tabela.delete(i)
        dados = carregar_json_seguro(ARQ_SUBSTANCIAS, {"versao":1, "substancias":[]})
        lista = dados.get("substancias", dados.get("substances", []))
        for s in lista:
            self.tabela.insert("", tk.END, values=(s.get("id",""), s.get("nome",""), s.get("data",""), s.get("status","")))

    def _selecionar(self, _):
        sel = self.tabela.selection()
        if not sel: return
        sid, nome, data, status = self.tabela.item(sel[0])["values"]
        self.var_id.set(str(sid)); self.var_nome.set(str(nome)); self.var_data.set(str(data)); self.var_status.set(str(status))

    def _limpar(self):
        self.var_id.set(""); self.var_nome.set(""); self.var_data.set(""); self.var_status.set("")

    def _salvar(self):
        sid = self.var_id.get().strip()
        nome = self.var_nome.get().strip()
        data_txt = self.var_data.get().strip()
        status = self.var_status.get().strip()

        if not sid or not nome:
            messagebox.showwarning("Campos", "Informe ao menos ID e Nome.")
            return
        if not data_txt:
            data_txt = agora_iso().split("T")[0]

        store = carregar_json_seguro(ARQ_SUBSTANCIAS, {"versao":1, "substancias":[]})
        lista = store.get("substancias", store.get("substances", []))
        existente = next((s for s in lista if s.get("id") == sid), None)
        if existente:
            existente["nome"] = nome; existente["data"] = data_txt; existente["status"] = status
            acao = "substancia_atualizar"
        else:
            lista.append({"id": sid, "nome": nome, "data": data_txt, "status": status})
            # se chave antiga existir, mantém compatibilidade ao salvar
            if "substances" in store and "substancias" not in store:
                store["substances"] = lista
            else:
                store["substancias"] = lista
            acao = "substancia_criar"

        # garantir chave preferida em pt-BR
        if "substancias" not in store:
            store["substancias"] = lista
        if "substances" in store:
            store.pop("substances", None)

        salvar_json(ARQ_SUBSTANCIAS, store)
        registrar_evento(ARQ_LOG, {"ts": agora_iso(), "tipo": acao, "id": sid})
        self._carregar(); self._limpar()

    def _deletar(self):
        sid = self.var_id.get().strip()
        if not sid:
            messagebox.showwarning("Seleção", "Selecione uma substância (ou informe o ID).")
            return
        if not messagebox.askyesno("Confirmar", f"Excluir substância '{sid}'?"):
            return
        store = carregar_json_seguro(ARQ_SUBSTANCIAS, {"versao":1, "substancias":[]})
        lista = store.get("substancias", store.get("substances", []))
        novo = [s for s in lista if s.get("id") != sid]
        if len(novo) == len(lista):
            messagebox.showinfo("Info", "ID não encontrado.")
            return
        # aplicar na chave preferida
        store["substancias"] = novo
        store.pop("substances", None)
        salvar_json(ARQ_SUBSTANCIAS, store)
        registrar_evento(ARQ_LOG, {"ts": agora_iso(), "tipo": "substancia_deletar", "id": sid})
        self._carregar(); self._limpar()

class TelaAmostras(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        ttk.Label(self, text="Visualização de Amostras (somente leitura)").pack(anchor=W)

class AplicacaoPrincipal(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("Controle de Acesso - Biotecnologia")
        self.geometry("1280x720")
        garantir_arquivos_dados()
        self._rotear()

    def _rotear(self):
        self._mostrar_login()

    def _limpar_raiz(self):
        for w in self.winfo_children(): w.destroy()

    def _mostrar_login(self):
        self._limpar_raiz()
        TelaLogin(self, ao_autenticar=self._apos_login)

    def _apos_login(self, usuario):
        self._limpar_raiz()
        abas = ttk.Notebook(self); abas.pack(fill=BOTH, expand=YES, padx=10, pady=10)
        if usuario["papel"] == "admin":
            abas.add(TelaSubstancias(abas), text="Substâncias")
            abas.add(TelaUsuarios(abas), text="Usuários")
        else:
            abas.add(TelaAmostras(abas), text="Amostras")
        barra = ttk.Frame(self); barra.pack(fill=X, padx=10, pady=(0,10))
        ttk.Label(barra, text=f"Logado: {usuario['nome']} ({usuario['papel']})").pack(side=LEFT)
        ttk.Button(barra, text="Sair", bootstyle=DANGER, command=self._mostrar_login).pack(side=RIGHT)

if __name__ == "__main__":
    AplicacaoPrincipal().mainloop()
