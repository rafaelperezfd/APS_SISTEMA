import json
import pathlib
import datetime
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# Caminhos dos arquivos 
PASTA_APP = pathlib.Path(__file__).resolve().parent
ARQ_USUARIOS = PASTA_APP / "usuarios.json"
ARQ_SUBSTANCIAS = PASTA_APP / "substancias.json"
ARQ_LOG = PASTA_APP / "entrada_saida.jsonl"

# Pegar tempo exato
def agora():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")
# Ler arquivo JSON
def ler_json(caminho: pathlib.Path, padrao: dict):
    try:
        if not caminho.exists():
            caminho.write_text(json.dumps(padrao, ensure_ascii=False, indent=2), "utf-8")
        texto = caminho.read_text("utf-8")
        return json.loads(texto) if texto.strip() else padrao
    except Exception:
        caminho.write_text(json.dumps(padrao, ensure_ascii=False, indent=2), "utf-8")
        return padrao

def salvar_json(caminho: pathlib.Path, dados: dict):
    caminho.write_text(json.dumps(dados, ensure_ascii=False, indent=2), "utf-8")
# Registrar login
def registrar_log(evento: dict):
    if not ARQ_LOG.exists():
        ARQ_LOG.touch()
    with ARQ_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(evento, ensure_ascii=False) + "\n")

# CRUD para usuario
def listar_usuarios():
    base = ler_json(ARQ_USUARIOS, {"versao": 1, "usuarios": []})
    return base.get("usuarios", [])

def salvar_usuarios(lista_usuarios: list):
    salvar_json(ARQ_USUARIOS, {"versao": 1, "usuarios": lista_usuarios})
# Busca o usuario
def buscar_usuario_por_cracha(cracha: str):
    lista_usuarios = listar_usuarios()
    for usuario in lista_usuarios:
        if usuario.get("cracha") == cracha:
            return usuario
    return None
# Cria o usuario
def criar_usuario(cracha: str, nome: str, papel: str, senha_plana: str):
    lista_usuarios = listar_usuarios()
    for usuario in lista_usuarios:
        if usuario.get("cracha") == cracha:
            raise ValueError("Crachá já existe")
    novo_usuario = {"cracha": cracha, "nome": nome, "papel": papel, "ativo": True, "senha_plana": senha_plana}
    lista_usuarios.append(novo_usuario)
    salvar_usuarios(lista_usuarios)
# Atualiza o usuario ja existente
def atualizar_usuario(cracha: str, nome: str, papel: str, nova_senha_plana: str | None):
    lista_usuarios = listar_usuarios()
    usuario_encontrado = None
    for usuario in lista_usuarios:
        if usuario.get("cracha") == cracha:
            usuario_encontrado = usuario
            break
    if usuario_encontrado is None:
        raise ValueError("Usuário não encontrado")
    usuario_encontrado["nome"] = nome
    usuario_encontrado["papel"] = papel
    usuario_encontrado["ativo"] = True
    if nova_senha_plana:
        usuario_encontrado["senha_plana"] = nova_senha_plana
    salvar_usuarios(lista_usuarios)
# Deletar usuario
def deletar_usuario(cracha: str):
    lista_usuarios = listar_usuarios()
    nova_lista = []
    for usuario in lista_usuarios:
        if usuario.get("cracha") != cracha:
            nova_lista.append(usuario)
    if len(nova_lista) == len(lista_usuarios):
        raise ValueError("Usuário não encontrado")
    salvar_usuarios(nova_lista)

# Senha plana é a senha normal do admin
def verificar_login(cracha: str, senha_digitada: str) -> dict | None:
    usuario = buscar_usuario_por_cracha(cracha)
    if not usuario or not usuario.get("ativo", True):
        return None
    senha_plana = usuario.get("senha_plana")
    if isinstance(senha_plana, str) and senha_digitada == senha_plana:
        return usuario
    return None

# CRUD de substâncias
# Consultas no banco de dados
def carregar_substancias():
    return ler_json(ARQ_SUBSTANCIAS, {"versao": 1, "substancias": []})

def salvar_base_substancias(base: dict):
    salvar_json(ARQ_SUBSTANCIAS, base)

def listar_substancias():
    base = carregar_substancias()
    return base.get("substancias", [])
# Cria a substancia
def criar_substancia(subst_id: str, nome: str, data: str, status: str):
    base = carregar_substancias()
    lista = base.get("substancias", [])
    for substancia in lista:
        if substancia.get("id") == subst_id:
            raise ValueError("ID já existe")
    nova = {"id": subst_id, "nome": nome, "data": data, "status": status}
    lista.append(nova)
    base["substancias"] = lista
    salvar_base_substancias(base)

def atualizar_substancia(subst_id: str, nome: str, data: str, status: str):
    base = carregar_substancias()
    lista = base.get("substancias", [])
    alvo = None
    for substancia in lista:
        if substancia.get("id") == subst_id:
            alvo = substancia
            break
    if alvo is None:
        raise ValueError("Substância não encontrada")
    alvo["nome"] = nome
    alvo["data"] = data
    alvo["status"] = status
    salvar_base_substancias(base)

def deletar_substancia(subst_id: str):
    base = carregar_substancias()
    lista = base.get("substancias", [])
    nova_lista = []
    for substancia in lista:
        if substancia.get("id") != subst_id:
            nova_lista.append(substancia)
    if len(nova_lista) == len(lista):
        raise ValueError("Substância não encontrada")
    base["substancias"] = nova_lista
    salvar_base_substancias(base)

# Tela de login
class TelaLogin(ttk.Frame):
    # Definindo o front-end com tkkbootstrap e juntando com back-end
    def __init__(self, master, ao_autenticar):
        super().__init__(master, padding=20)
        self.ao_autenticar = ao_autenticar
        self.cracha_var = tk.StringVar()
        self.senha_var = tk.StringVar()

        ttk.Label(self, text="Login", font=("-size", 16)).pack(pady=(0, 12))
        frame = ttk.Frame(self); frame.pack(fill=X)

        ttk.Label(frame, text="Crachá:").grid(row=0, column=0, sticky=W, pady=6)
        ttk.Entry(frame, textvariable=self.cracha_var, width=32).grid(row=0, column=1, sticky=EW, padx=6)
        ttk.Label(frame, text="Senha:").grid(row=1, column=0, sticky=W, pady=6)
        ttk.Entry(frame, textvariable=self.senha_var, show="•", width=32).grid(row=1, column=1, sticky=EW, padx=6)

        botoes = ttk.Frame(self); botoes.pack(pady=12)
        ttk.Button(botoes, text="Entrar", bootstyle=SUCCESS, command=self._entrar).pack(side=LEFT, padx=6)
        ttk.Button(botoes, text="Fechar", bootstyle=DANGER, command=self.quit).pack(side=LEFT, padx=6)

        frame.columnconfigure(1, weight=1)
        self.pack(fill=BOTH, expand=YES)

    def _entrar(self):
        cracha = self.cracha_var.get().strip()
        senha = self.senha_var.get()
        usuario = verificar_login(cracha, senha)
        if not usuario:
            messagebox.showerror("Acesso negado", "Crachá/Senha inválidos.")
            registrar_log({"ts": agora(), "tipo": "login", "cracha": cracha, "resultado": "negado"})
            return
        registrar_log({"ts": agora(), "tipo": "login", "cracha": usuario["cracha"], "resultado": "permitido"})
        self.ao_autenticar(usuario)
# Tela de usuario
class TelaUsuarios(ttk.Frame):
    # Definindo o front-end com tkkbootstrap e juntando com back-end
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.cracha_var = tk.StringVar()
        self.nome_var = tk.StringVar()
        self.papel_var = tk.StringVar(value="user")
        self.senha_var = tk.StringVar()

        grupo = ttk.Labelframe(self, text="Usuários", padding=12); grupo.pack(fill=X)
        ttk.Label(grupo, text="Crachá:").grid(row=0, column=0, sticky=W)
        ttk.Entry(grupo, textvariable=self.cracha_var).grid(row=0, column=1, sticky=EW, padx=6)
        ttk.Label(grupo, text="Nome:").grid(row=1, column=0, sticky=W)
        ttk.Entry(grupo, textvariable=self.nome_var).grid(row=1, column=1, sticky=EW, padx=6)
        ttk.Label(grupo, text="Papel:").grid(row=2, column=0, sticky=W)
        ttk.Combobox(grupo, textvariable=self.papel_var, values=["admin", "user"], state="readonly").grid(row=2, column=1, sticky=EW, padx=6)
        ttk.Label(grupo, text="Senha:").grid(row=3, column=0, sticky=W)
        ttk.Entry(grupo, textvariable=self.senha_var, show="•").grid(row=3, column=1, sticky=EW, padx=6)

        barra = ttk.Frame(grupo); barra.grid(row=4, column=0, columnspan=2, pady=8)
        ttk.Button(barra, text="Salvar", bootstyle=PRIMARY, command=self._salvar).pack(side=LEFT, padx=5)
        ttk.Button(barra, text="Deletar", bootstyle=DANGER, command=self._deletar).pack(side=LEFT, padx=5)
        ttk.Button(barra, text="Limpar", bootstyle=SECONDARY, command=self._limpar).pack(side=LEFT, padx=5)
        grupo.columnconfigure(1, weight=1)
        # larguras e cabeçalho
        self.tabela = ttk.Treeview(self, columns=("cracha", "nome", "papel"), show="headings", height=10, bootstyle=INFO)
        for coluna, titulo in zip(("cracha", "nome", "papel"), ("Crachá", "Nome", "Papel")):
            self.tabela.heading(coluna, text=titulo)
            self.tabela.column(coluna, width=220 if coluna != "papel" else 120)
        self.tabela.pack(fill=BOTH, expand=YES, pady=8)
        self.tabela.bind("<<TreeviewSelect>>", self._selecionar)

        self._recarregar()
    # CRUD PARA USUARIOS
    def _recarregar(self):
        for item in self.tabela.get_children():
            self.tabela.delete(item)
        for usuario in listar_usuarios():
            self.tabela.insert("", tk.END, values=(usuario["cracha"], usuario["nome"], usuario["papel"]))

    def _limpar(self):
        self.cracha_var.set("")
        self.nome_var.set("")
        self.papel_var.set("user")
        self.senha_var.set("")

    def _selecionar(self, _):
        if not self.tabela.selection():
            return
        cracha, nome, papel = self.tabela.item(self.tabela.selection()[0])["values"]
        self.cracha_var.set(cracha)
        self.nome_var.set(nome)
        self.papel_var.set(papel)
        self.senha_var.set("")

    def _salvar(self):
        cracha = self.cracha_var.get().strip()
        nome = self.nome_var.get().strip()
        papel = self.papel_var.get().strip()
        senha = self.senha_var.get()
        if not cracha or not nome:
            messagebox.showwarning("Campos", "Informe crachá e nome.")
            return
        try:
            if buscar_usuario_por_cracha(cracha):
                atualizar_usuario(cracha, nome, papel, senha if senha else None)
            else:
                criar_usuario(cracha, nome, papel, senha)
            registrar_log({"ts": agora(), "tipo": "usuario_salvar", "cracha": cracha})
            self._recarregar()
            self._limpar()
        except ValueError as erro:
            messagebox.showinfo("Info", str(erro))

    def _deletar(self):
        cracha = self.cracha_var.get().strip()
        if not cracha:
            messagebox.showwarning("Seleção", "Escolha um usuário.")
            return
        try:
            deletar_usuario(cracha)
            registrar_log({"ts": agora(), "tipo": "usuario_deletar", "cracha": cracha})
            self._recarregar()
            self._limpar()
        except ValueError as erro:
            messagebox.showinfo("Info", str(erro))
# Tela de substancias
class TelaSubstanciasAdmin(ttk.Frame):
    # Definindo o front-end com tkkbootstrap e juntando com back-end
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.id_var = tk.StringVar()
        self.nome_var = tk.StringVar()
        self.data_var = tk.StringVar()
        self.status_var = tk.StringVar()

        grupo = ttk.Labelframe(self, text="Cadastro de Substâncias", padding=10); grupo.pack(fill=X, pady=(0, 8))
        ttk.Label(grupo, text="ID").grid(row=0, column=0, sticky=W); ttk.Entry(grupo, textvariable=self.id_var, width=24).grid(row=0, column=1, sticky=EW, padx=6)
        ttk.Label(grupo, text="Nome").grid(row=0, column=2, sticky=W); ttk.Entry(grupo, textvariable=self.nome_var, width=36).grid(row=0, column=3, sticky=EW, padx=6)
        ttk.Label(grupo, text="Data").grid(row=1, column=0, sticky=W); ttk.Entry(grupo, textvariable=self.data_var, width=24).grid(row=1, column=1, sticky=EW, padx=6)
        ttk.Label(grupo, text="Status").grid(row=1, column=2, sticky=W); ttk.Entry(grupo, textvariable=self.status_var, width=24).grid(row=1, column=3, sticky=EW, padx=6)

        barra = ttk.Frame(grupo); barra.grid(row=2, column=0, columnspan=4, sticky=W, pady=8)
        ttk.Button(barra, text="Salvar", bootstyle=PRIMARY, command=self._salvar).pack(side=LEFT, padx=4)
        ttk.Button(barra, text="Deletar", bootstyle=DANGER, command=self._deletar).pack(side=LEFT, padx=4)
        ttk.Button(barra, text="Limpar", bootstyle=SECONDARY, command=self._limpar).pack(side=LEFT, padx=4)
        # Cabeçalhos
        self.tabela = ttk.Treeview(self, columns=("id", "nome", "data", "status"), show="headings", bootstyle=INFO, height=12)
        for coluna in ("id", "nome", "data", "status"):
            self.tabela.heading(coluna, text=coluna.upper() if coluna != "nome" else "Nome")
        # larguras
        self.tabela.column("id", width=140)
        self.tabela.column("nome", width=260)
        self.tabela.column("data", width=160)
        self.tabela.column("status", width=160)
        self.tabela.pack(fill=BOTH, expand=YES)
        self.tabela.bind("<<TreeviewSelect>>", self._selecionar)

        self._carregar()
    # CRUD PARA SUBSTANCIAS
    def _carregar(self):
        for item in self.tabela.get_children():
            self.tabela.delete(item)
        for subst in listar_substancias():
            self.tabela.insert("", tk.END, values=(subst.get("id", ""), subst.get("nome", ""), subst.get("data", ""), subst.get("status", "")))

    def _selecionar(self, _):
        if not self.tabela.selection():
            return
        subst_id, nome, data, status = self.tabela.item(self.tabela.selection()[0])["values"]
        self.id_var.set(str(subst_id))
        self.nome_var.set(str(nome))
        self.data_var.set(str(data))
        self.status_var.set(str(status))

    def _limpar(self):
        self.id_var.set("")
        self.nome_var.set("")
        self.data_var.set("")
        self.status_var.set("")

    def _salvar(self):
        subst_id = self.id_var.get().strip()
        nome = self.nome_var.get().strip()
        data = self.data_var.get().strip()
        status = self.status_var.get().strip()
        if not subst_id or not nome:
            messagebox.showwarning("Campos", "Informe ao menos ID e Nome.")
            return
        if not data:
            data = agora().split("T")[0]
        try:
            existe = False
            for subst in listar_substancias():
                if subst.get("id") == subst_id:
                    existe = True
                    break
            if existe:
                atualizar_substancia(subst_id, nome, data, status)
                registrar_log({"ts": agora(), "tipo": "substancia_atualizar", "id": subst_id})
            else:
                criar_substancia(subst_id, nome, data, status)
                registrar_log({"ts": agora(), "tipo": "substancia_criar", "id": subst_id})
            self._carregar()
            self._limpar()
        except ValueError as erro:
            messagebox.showinfo("Info", str(erro))

    def _deletar(self):
        subst_id = self.id_var.get().strip()
        if not subst_id:
            messagebox.showwarning("Seleção", "Informe o ID.")
            return
        try:
            deletar_substancia(subst_id)
            registrar_log({"ts": agora(), "tipo": "substancia_deletar", "id": subst_id})
            self._carregar()
            self._limpar()
        except ValueError as erro:
            messagebox.showinfo("Info", str(erro))
# Interface de substancias para o usuario normal
class TelaSubstanciasLeitura(ttk.Frame):
    # Definindo o front-end com tkkbootstrap e juntando com back-end
    def __init__(self, master):
        super().__init__(master, padding=10)
        # cabeçalhos
        self.tabela = ttk.Treeview(self, columns=("id", "nome", "data", "status"), show="headings", bootstyle=INFO, height=14)
        for coluna in ("id", "nome", "data", "status"):
            self.tabela.heading(coluna, text=coluna.upper() if coluna != "nome" else "Nome")
        # larguras
        self.tabela.column("id", width=140)
        self.tabela.column("nome", width=260)
        self.tabela.column("data", width=160) 
        self.tabela.column("status", width=160)
        self.tabela.pack(fill=BOTH, expand=YES, pady=(0, 8))
        self._carregar()

    def _carregar(self):
        for item in self.tabela.get_children():
            self.tabela.delete(item)
        for subst in listar_substancias():
            self.tabela.insert("", tk.END, values=(subst.get("id", ""), subst.get("nome", ""), subst.get("data", ""), subst.get("status", "")))

# Interface de entradas para admin
class TelaEntradas(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        colunas = ("ts", "tipo", "cracha", "id")  
        self.tabela = ttk.Treeview(self, columns=colunas, show="headings", bootstyle=INFO, height=16)
        # cabeçalhos
        titulos = {"ts": "Data/Hora", "tipo": "Tipo", "cracha": "Crachá", "id": "ID"}
        for coluna in colunas:
            self.tabela.heading(coluna, text=titulos[coluna])
        # larguras
        self.tabela.column("ts", width=180)
        self.tabela.column("tipo", width=140)
        self.tabela.column("cracha", width=140)
        self.tabela.column("id", width=140)
        self.tabela.pack(fill=BOTH, expand=YES, pady=(0, 8))
        self._carregar()

    def _carregar(self):
        for item in self.tabela.get_children():
            self.tabela.delete(item)
        if not ARQ_LOG.exists():
            return
        with ARQ_LOG.open("r", encoding="utf-8") as f:
            for linha in f:
                try:
                    evento = json.loads(linha)
                except json.JSONDecodeError:
                    continue
                self.tabela.insert(
                    "",
                    tk.END,
                    values=(evento.get("ts", ""), evento.get("tipo", ""), evento.get("cracha", ""), evento.get("id", ""))
                )

# Interface inteira para aplicação
class Aplicacao(ttk.Window):
    # Tela inicial com dimensões iniciais
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("Controle de Acesso - Simples")
        self.geometry("1000x620")
        _ = ler_json(ARQ_USUARIOS, {"versao": 1, "usuarios": []})
        _ = ler_json(ARQ_SUBSTANCIAS, {"versao": 1, "substancias": []})
        if not ARQ_LOG.exists():
            ARQ_LOG.touch()
        self._mostrar_login()

    def _limpar(self):
        for widget in self.winfo_children():
            widget.destroy()
    # Tela de login
    def _mostrar_login(self):
        self._limpar()
        TelaLogin(self, ao_autenticar=self._apos_login)
    # Mostrar partes do admin ou do usuario normal
    def _apos_login(self, usuario):
        self._limpar()
        abas = ttk.Notebook(self); abas.pack(fill=BOTH, expand=YES, padx=10, pady=10)
        if usuario["papel"] == "admin":
            abas.add(TelaSubstanciasAdmin(abas), text="Substâncias")
            abas.add(TelaUsuarios(abas), text="Usuários")
            abas.add(TelaEntradas(abas), text="Entradas")
        else:
            abas.add(TelaSubstanciasLeitura(abas), text="Substâncias")
        barra = ttk.Frame(self); barra.pack(fill=X, padx=10, pady=(0, 10))
        ttk.Label(barra, text=f"Logado: {usuario['nome']} ({usuario['papel']})").pack(side=LEFT)
        ttk.Button(barra, text="Sair", bootstyle=DANGER, command=lambda: self._fazer_logout(usuario)).pack(side=RIGHT)
    # Para logica de entradas e saidas
    def _fazer_logout(self, usuario):
        registrar_log({"ts": agora(), "tipo": "logout", "cracha": usuario["cracha"], "resultado": "saida"})
        self._mostrar_login()
# Para definitivamente rodar o código
if __name__ == "__main__":
    Aplicacao().mainloop()
