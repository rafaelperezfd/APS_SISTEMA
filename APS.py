import json, pathlib, datetime
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# Caminhos de arquivos
DIRETORIO_APP = pathlib.Path(__file__).resolve().parent
ARQUIVO_USUARIOS = DIRETORIO_APP / "usuarios.json"
ARQUIVO_SUBSTANCIAS = DIRETORIO_APP / "substancias.json"
ARQUIVO_ENTRADAS = DIRETORIO_APP / "entrada_saida.jsonl"

# Função para pegar tempo atual da biblioteca DateTime
def timestamp_atual():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")
# função para carrevar todos os DB do sistema
def carregar_json(caminho_arquivo: pathlib.Path, conteudo_padrao: dict):
    try:
        if not caminho_arquivo.exists():
            caminho_arquivo.write_text(json.dumps(conteudo_padrao, ensure_ascii=False, indent=2), "utf-8")
        texto = caminho_arquivo.read_text("utf-8")
        return json.loads(texto) if texto.strip() else conteudo_padrao
    except Exception:
        caminho_arquivo.write_text(json.dumps(conteudo_padrao, ensure_ascii=False, indent=2), "utf-8")
        return conteudo_padrao

def salvar_json(caminho_arquivo: pathlib.Path, dados: dict):
    caminho_arquivo.write_text(json.dumps(dados, ensure_ascii=False, indent=2), "utf-8")

def registrar_evento(evento: dict):
    if not ARQUIVO_ENTRADAS.exists():
        ARQUIVO_ENTRADAS.touch()
    with ARQUIVO_ENTRADAS.open("a", encoding="utf-8") as arquivo:
        arquivo.write(json.dumps(evento, ensure_ascii=False) + "\n")

#dados para usuários e substâncias
def carregar_usuarios():
    return carregar_json(ARQUIVO_USUARIOS, {"versao": 1, "usuarios": []})["usuarios"]

def salvar_usuarios(lista_usuarios: list):
    salvar_json(ARQUIVO_USUARIOS, {"versao": 1, "usuarios": lista_usuarios})

def buscar_usuario_por_cracha(cracha: str):
    lista = carregar_usuarios()
    return next((u for u in lista if u.get("cracha") == cracha), None)

def credenciais_validas(senha_digitada: str, usuario_encontrado: dict) -> bool:
    senha_plana = usuario_encontrado.get("senha_plana")
    return isinstance(senha_plana, str) and (senha_digitada == senha_plana)

def carregar_substancias():
    return carregar_json(ARQUIVO_SUBSTANCIAS, {"versao": 1, "substancias": []})

def salvar_substancias(dados_substancias: dict):
    salvar_json(ARQUIVO_SUBSTANCIAS, dados_substancias)

# Parte de interface visual feita com o TTKBOOTSTRAP
class TelaLogin(ttk.Frame):
    def __init__(self, master, callback_autenticado):
        super().__init__(master, padding=20)
        self.callback_autenticado = callback_autenticado
        self.var_cracha = tk.StringVar()
        self.var_senha = tk.StringVar()
        ttk.Label(self, text="Login", font=("-size", 16)).pack(pady=(0, 12))
        frame_campos = ttk.Frame(self); frame_campos.pack(fill=X)
        ttk.Label(frame_campos, text="Crachá:").grid(row=0, column=0, sticky=W, pady=6)
        ttk.Entry(frame_campos, textvariable=self.var_cracha, width=32).grid(row=0, column=1, sticky=EW, padx=6)
        ttk.Label(frame_campos, text="Senha:").grid(row=1, column=0, sticky=W, pady=6)
        ttk.Entry(frame_campos, textvariable=self.var_senha, show="•", width=32).grid(row=1, column=1, sticky=EW, padx=6)
        frame_botoes = ttk.Frame(self); frame_botoes.pack(pady=12)
        ttk.Button(frame_botoes, text="Entrar", bootstyle=SUCCESS, command=self._fazer_login).pack(side=LEFT, padx=6)
        ttk.Button(frame_botoes, text="Fechar", bootstyle=DANGER, command=self.quit).pack(side=LEFT, padx=6)
        frame_campos.columnconfigure(1, weight=1)
        self.pack(fill=BOTH, expand=YES)
    # feito o login é executado essa função para registrar entrada
    def _fazer_login(self):
        cracha_digitado = self.var_cracha.get().strip()
        senha_digitada = self.var_senha.get()
        usuario_encontrado = buscar_usuario_por_cracha(cracha_digitado)
        if not usuario_encontrado or not usuario_encontrado.get("ativo", True) or not credenciais_validas(senha_digitada, usuario_encontrado):
            messagebox.showerror("Acesso negado", "Crachá/Senha inválidos.")
            registrar_evento({"ts": timestamp_atual(), "tipo": "login", "cracha": cracha_digitado, "resultado": "negado"})
            return
        registrar_evento({"ts": timestamp_atual(), "tipo": "login", "cracha": usuario_encontrado["cracha"], "resultado": "permitido"})
        self.callback_autenticado(usuario_encontrado)
# Interface visual para os dois tipos de usuarios ADMIN e USUARIO NORMAL
class TelaUsuarios(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.var_cracha = tk.StringVar()
        self.var_nome = tk.StringVar()
        self.var_papel = tk.StringVar(value="user")
        self.var_senha = tk.StringVar()
        grupo = ttk.Labelframe(self, text="Usuários", padding=12); grupo.pack(fill=X)
        ttk.Label(grupo, text="Crachá:").grid(row=0, column=0, sticky=W)
        ttk.Entry(grupo, textvariable=self.var_cracha).grid(row=0, column=1, sticky=EW, padx=6)
        ttk.Label(grupo, text="Nome:").grid(row=1, column=0, sticky=W)
        ttk.Entry(grupo, textvariable=self.var_nome).grid(row=1, column=1, sticky=EW, padx=6)
        ttk.Label(grupo, text="Papel:").grid(row=2, column=0, sticky=W)
        ttk.Combobox(grupo, textvariable=self.var_papel, values=["admin", "user"], state="readonly").grid(row=2, column=1, sticky=EW, padx=6)
        ttk.Label(grupo, text="Senha (texto):").grid(row=3, column=0, sticky=W)
        ttk.Entry(grupo, textvariable=self.var_senha, show="•").grid(row=3, column=1, sticky=EW, padx=6)
        barra = ttk.Frame(grupo); barra.grid(row=4, column=0, columnspan=2, pady=8)
        ttk.Label(barra,text="Clique na linha do usuário para editar").pack(side=LEFT, padx=5)
        ttk.Button(barra, text="Salvar", bootstyle=PRIMARY, command=self._salvar_usuario).pack(side=LEFT, padx=5)
        ttk.Button(barra, text="Deletar", bootstyle=DANGER, command=self._deletar_usuario).pack(side=LEFT, padx=5)
        grupo.columnconfigure(1, weight=1)
        self.grid_usuarios = ttk.Treeview(self, columns=("cracha", "nome", "papel"), show="headings", height=10, bootstyle=INFO)
        for coluna, titulo in zip(("cracha", "nome", "papel"), ("Crachá", "Nome", "Papel")):
            self.grid_usuarios.heading(coluna, text=titulo); self.grid_usuarios.column(coluna, width=200 if coluna != "papel" else 120)
        self.grid_usuarios.pack(fill=BOTH, expand=YES, pady=8); self.grid_usuarios.bind("<<TreeviewSelect>>", self._selecionar_linha)
        self._recarregar()

    def _recarregar(self):
        for item in self.grid_usuarios.get_children(): self.grid_usuarios.delete(item)
        for usuario in carregar_usuarios():
            self.grid_usuarios.insert("", tk.END, values=(usuario["cracha"], usuario["nome"], usuario["papel"]))

    def _limpar_formulario(self):
        self.var_cracha.set(""); self.var_nome.set(""); self.var_papel.set("user"); self.var_senha.set("")

    def _selecionar_linha(self, _):
        if not self.grid_usuarios.selection(): return
        cracha, nome, papel = self.grid_usuarios.item(self.grid_usuarios.selection()[0])["values"]
        self.var_cracha.set(cracha); self.var_nome.set(nome); self.var_papel.set(papel); self.var_senha.set("")

    def _salvar_usuario(self):
        cracha = self.var_cracha.get().strip(); nome = self.var_nome.get().strip(); papel = self.var_papel.get().strip(); senha_nova = self.var_senha.get()
        if not cracha or not nome:
            messagebox.showwarning("Campos", "Informe crachá e nome."); return
        lista = carregar_usuarios()
        existente = next((u for u in lista if u["cracha"] == cracha), None)
        if existente:
            existente["nome"] = nome; existente["papel"] = papel; existente["ativo"] = True
            if senha_nova: existente["senha_plana"] = senha_nova
        else:
            lista.append({"cracha": cracha, "nome": nome, "papel": papel, "ativo": True, "senha_plana": senha_nova})
        salvar_usuarios(lista); registrar_evento({"ts": timestamp_atual(), "tipo": "usuario_salvar", "cracha": cracha}); self._recarregar(); self._limpar_formulario()

    def _deletar_usuario(self):
        cracha = self.var_cracha.get().strip()
        if not cracha: messagebox.showwarning("Seleção", "Escolha um usuário."); return
        lista = carregar_usuarios()
        nova_lista = [u for u in lista if u["cracha"] != cracha]
        if len(nova_lista) == len(lista):
            messagebox.showinfo("Info", "Crachá não encontrado."); return
        salvar_usuarios(nova_lista); registrar_evento({"ts": timestamp_atual(), "tipo": "usuario_deletar", "cracha": cracha}); self._recarregar(); self._limpar_formulario()

# Tela para parte de CRUD no sistema de substancias
class TelaSubstanciasAdmin(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.var_id = tk.StringVar(); self.var_nome = tk.StringVar(); self.var_data = tk.StringVar(); self.var_status = tk.StringVar()
        grupo = ttk.Labelframe(self, text="Cadastro de Substâncias", padding=10); grupo.pack(fill=X, pady=(0, 8))
        ttk.Label(grupo, text="ID").grid(row=0, column=0, sticky=W); ttk.Entry(grupo, textvariable=self.var_id, width=24).grid(row=0, column=1, sticky=EW, padx=6)
        ttk.Label(grupo, text="Nome").grid(row=0, column=2, sticky=W); ttk.Entry(grupo, textvariable=self.var_nome, width=36).grid(row=0, column=3, sticky=EW, padx=6)
        ttk.Label(grupo, text="Data").grid(row=1, column=0, sticky=W); ttk.Entry(grupo, textvariable=self.var_data, width=24).grid(row=1, column=1, sticky=EW, padx=6)
        ttk.Label(grupo, text="Status").grid(row=1, column=2, sticky=W); ttk.Entry(grupo, textvariable=self.var_status, width=24).grid(row=1, column=3, sticky=EW, padx=6)
        barra = ttk.Frame(grupo); barra.grid(row=2, column=0, columnspan=4, sticky=W, pady=8)
        ttk.Label(barra, text="Clique na linha da substancia para editar").pack(side=LEFT, padx=4)
        ttk.Button(barra, text="Salvar", bootstyle=PRIMARY, command=self._salvar).pack(side=LEFT, padx=4)
        ttk.Button(barra, text="Deletar", bootstyle=DANGER, command=self._deletar).pack(side=LEFT, padx=4)
        for col in (1, 3): grupo.columnconfigure(col, weight=1)

        self.grid_substancias = ttk.Treeview(self, columns=("id", "nome", "data", "status"), show="headings", bootstyle=INFO, height=12)
        for coluna in ("id", "nome", "data", "status"):
            self.grid_substancias.heading(coluna, text=coluna.upper() if coluna != "nome" else "Nome")
        self.grid_substancias.column("id", width=140); self.grid_substancias.column("nome", width=260); self.grid_substancias.column("data", width=160); self.grid_substancias.column("status", width=160)
        self.grid_substancias.pack(fill=BOTH, expand=YES); self.grid_substancias.bind("<<TreeviewSelect>>", self._selecionar)
        self._carregar()

    def _carregar(self):
        for item in self.grid_substancias.get_children(): self.grid_substancias.delete(item)
        dados = carregar_substancias()
        for subst in dados.get("substancias", []):
            self.grid_substancias.insert("", tk.END, values=(subst.get("id", ""), subst.get("nome", ""), subst.get("data", ""), subst.get("status", "")))

    def _selecionar(self, _):
        if not self.grid_substancias.selection(): return
        sid, nome, data, status = self.grid_substancias.item(self.grid_substancias.selection()[0])["values"]
        self.var_id.set(str(sid)); self.var_nome.set(str(nome)); self.var_data.set(str(data)); self.var_status.set(str(status))

    def _limpar(self):
        self.var_id.set(""); self.var_nome.set(""); self.var_data.set(""); self.var_status.set("")

    def _salvar(self):
        sid = self.var_id.get().strip(); nome = self.var_nome.get().strip(); data = self.var_data.get().strip(); status = self.var_status.get().strip()
        if not sid or not nome:
            messagebox.showwarning("Campos", "Informe ao menos ID e Nome."); return
        if not data: data = timestamp_atual().split("T")[0]
        store = carregar_substancias(); lista = store.get("substancias", [])
        existente = next((s for s in lista if s.get("id") == sid), None)
        acao = "substancia_atualizar" if existente else "substancia_criar"
        if existente: existente.update({"nome": nome, "data": data, "status": status})
        else: lista.append({"id": sid, "nome": nome, "data": data, "status": status}); store["substancias"] = lista
        salvar_substancias(store); registrar_evento({"ts": timestamp_atual(), "tipo": acao, "id": sid}); self._carregar(); self._limpar()

    def _deletar(self):
        sid = self.var_id.get().strip()
        if not sid:
            messagebox.showwarning("Seleção", "Informe o ID."); return
        store = carregar_substancias(); lista = store.get("substancias", [])
        nova_lista = [s for s in lista if s.get("id") != sid]
        if len(nova_lista) == len(lista):
            messagebox.showinfo("Info", "ID não encontrado."); return
        store["substancias"] = nova_lista; salvar_substancias(store); registrar_evento({"ts": timestamp_atual(), "tipo": "substancia_deletar", "id": sid}); self._carregar(); self._limpar()
# Feito apenas para o usuario ter alguma interação no sistema proposto
class TelaSubstanciasLeitura(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.grid_substancias = ttk.Treeview(self, columns=("id", "nome", "data", "status"), show="headings", bootstyle=INFO, height=14)
        for coluna in ("id", "nome", "data", "status"):
            self.grid_substancias.heading(coluna, text=coluna.upper() if coluna != "nome" else "Nome")
        self.grid_substancias.column("id", width=140); self.grid_substancias.column("nome", width=260); self.grid_substancias.column("data", width=160); self.grid_substancias.column("status", width=160)
        self.grid_substancias.pack(fill=BOTH, expand=YES, pady=(0, 8))
        ttk.Button(self, text="Recarregar", bootstyle=INFO, command=self._carregar).pack(anchor=W)
        self._carregar()

    def _carregar(self):
        for item in self.grid_substancias.get_children(): self.grid_substancias.delete(item)
        dados = carregar_substancias()
        for subst in dados.get("substancias", []):
            self.grid_substancias.insert("", tk.END, values=(subst.get("id", ""), subst.get("nome", ""), subst.get("data", ""), subst.get("status", "")))
# Parte visual para admin, para visualizar entrada e saidas
class TelaEntradas(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        colunas = ("ts", "tipo", "cracha", "id", "detalhes")
        self.grid_entradas = ttk.Treeview(self, columns=colunas, show="headings", bootstyle=INFO, height=16)
        for coluna, titulo in zip(colunas, ("Data/Hora", "Tipo", "Crachá", "ID", "Detalhes")):
            self.grid_entradas.heading(coluna, text=titulo)
        self.grid_entradas.column("ts", width=180); self.grid_entradas.column("tipo", width=140); self.grid_entradas.column("cracha", width=140); self.grid_entradas.column("id", width=140); self.grid_entradas.column("detalhes", width=200)
        self.grid_entradas.pack(fill=BOTH, expand=YES, pady=(0, 8))
        ttk.Button(self, text="Recarregar", bootstyle=INFO, command=self._carregar).pack(anchor=W)
        self._carregar()

    def _carregar(self):
        for item in self.grid_entradas.get_children(): self.grid_entradas.delete(item)
        if not ARQUIVO_ENTRADAS.exists(): return
        with ARQUIVO_ENTRADAS.open("r", encoding="utf-8") as arquivo:
            for linha in arquivo:
                try:
                    evento = json.loads(linha)
                except json.JSONDecodeError:
                    continue
                self.grid_entradas.insert("", tk.END, values=(evento.get("ts", ""), evento.get("tipo", ""), evento.get("cracha", ""), evento.get("id", ""), ""))

# De fato, aonde é feito a janela e a junção das outras funções para funcionar o sistema
class Aplicacao(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("Controle de Acesso - Enxuto"); self.geometry("1000x620")
        _ = carregar_json(ARQUIVO_USUARIOS, {"versao": 1, "usuarios": []}); _ = carregar_json(ARQUIVO_SUBSTANCIAS, {"versao": 1, "substancias": []})
        if not ARQUIVO_ENTRADAS.exists(): ARQUIVO_ENTRADAS.touch()
        self._mostrar_login()

    def _limpar_janela(self):
        for widget in self.winfo_children(): widget.destroy()

    def _mostrar_login(self):
        self._limpar_janela(); TelaLogin(self, callback_autenticado=self._apos_login)

    def _apos_login(self, usuario_autenticado):
        self._limpar_janela()
        abas = ttk.Notebook(self); abas.pack(fill=BOTH, expand=YES, padx=10, pady=10)
        if usuario_autenticado["papel"] == "admin":
            abas.add(TelaSubstanciasAdmin(abas), text="Substâncias"); abas.add(TelaUsuarios(abas), text="Usuários"); abas.add(TelaEntradas(abas), text="Entradas")
        else:
            abas.add(TelaSubstanciasLeitura(abas), text="Substâncias")
        barra = ttk.Frame(self); barra.pack(fill=X, padx=10, pady=(0, 10))
        ttk.Label(barra, text=f"Logado: {usuario_autenticado['nome']} ({usuario_autenticado['papel']})").pack(side=LEFT)
        ttk.Button(barra, text="Sair", bootstyle=DANGER, command=lambda: self._fazer_logout(usuario_autenticado)).pack(side=RIGHT)

    def _fazer_logout(self, usuario_autenticado):
        registrar_evento({"ts": timestamp_atual(), "tipo": "logout", "cracha": usuario_autenticado["cracha"], "resultado": "saida"})
        self._mostrar_login()

if __name__ == "__main__":
    Aplicacao().mainloop()
