import json, os, base64, secrets, hashlib, pathlib, datetime
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

APP_DIR = pathlib.Path(__file__).resolve().parent
USERS_FILE = APP_DIR / "users.json"
SUBS_FILE  = APP_DIR / "substances.json"
SAMP_FILE  = APP_DIR / "samples.json"
LOG_FILE   = APP_DIR / "audit_log.jsonl"

SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LEN = 16384, 8, 1, 64

def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")

def scrypt_hash(password: str, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=KEY_LEN)
    return {
        "salt_b64": base64.b64encode(salt).decode(),
        "hash_b64": base64.b64encode(dk).decode(),
        "params": {"n": n, "r": r, "p": p}
    }

def scrypt_verify(password: str, pwd_obj: dict) -> bool:
    salt = base64.b64decode(pwd_obj["salt_b64"])
    exp  = base64.b64decode(pwd_obj["hash_b64"])
    n = int(pwd_obj["params"]["n"]); r = int(pwd_obj["params"]["r"]); p = int(pwd_obj["params"]["p"])
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(exp))
    return secrets.compare_digest(dk, exp)

def jl_append(path: pathlib.Path, event: dict):
    line = json.dumps(event, ensure_ascii=False)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def atomic_write(path: pathlib.Path, data: dict):
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

# --------- NOVO: carregamento robusto ---------
def load_json_safe(path: pathlib.Path, default_obj: dict) -> dict:
    """
    Lê JSON tolerando arquivo ausente, vazio ou corrompido.
    Se necessário, grava 'default_obj' e retorna o default.
    """
    try:
        if not path.exists() or path.stat().st_size == 0:
            atomic_write(path, default_obj)
            return default_obj
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        if not raw.strip():
            atomic_write(path, default_obj)
            return default_obj
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise json.JSONDecodeError("Root must be object", raw, 0)
        return data
    except json.JSONDecodeError:
        # repara arquivo inválido
        atomic_write(path, default_obj)
        return default_obj
# -----------------------------------------------

def ensure_data_files():
    # cria se ausente; conteúdo será normalizado por load_json_safe
    if not USERS_FILE.exists():
        atomic_write(USERS_FILE, {"version":1, "users":[]})
    if not SUBS_FILE.exists():
        atomic_write(SUBS_FILE, {"version":1, "substances":[]})
    if not SAMP_FILE.exists():
        atomic_write(SAMP_FILE, {"version":1, "samples":[]})
    if not LOG_FILE.exists():
        LOG_FILE.touch()

def save_json(path: pathlib.Path, data: dict):
    atomic_write(path, data)

def find_user(badge_id):
    data = load_json_safe(USERS_FILE, {"version":1, "users":[]})
    for u in data["users"]:
        if u["badge_id"] == badge_id:
            return u, data
    return None, data

class FirstAdminDialog(ttk.Toplevel):
    def __init__(self, master, on_done):
        super().__init__(master)
        self.title("Criar primeiro administrador")
        self.transient(master)
        self.grab_set()
        self.resizable(False, False)

        self.badge = tk.StringVar(value="ADMIN001")
        self.name  = tk.StringVar(value="Administrador")
        self.pass1 = tk.StringVar()
        self.pass2 = tk.StringVar()

        frm = ttk.Labelframe(self, text="Cadastro inicial", padding=12)
        frm.pack(fill=BOTH, expand=YES, padx=12, pady=12)

        ttk.Label(frm, text="Crachá:").grid(row=0, column=0, sticky=W, pady=4)
        ttk.Entry(frm, textvariable=self.badge, width=28).grid(row=0, column=1, sticky=EW, padx=6)

        ttk.Label(frm, text="Nome:").grid(row=1, column=0, sticky=W, pady=4)
        ttk.Entry(frm, textvariable=self.name).grid(row=1, column=1, sticky=EW, padx=6)

        ttk.Label(frm, text="Senha:").grid(row=2, column=0, sticky=W, pady=4)
        ttk.Entry(frm, textvariable=self.pass1, show="•").grid(row=2, column=1, sticky=EW, padx=6)

        ttk.Label(frm, text="Confirmar senha:").grid(row=3, column=0, sticky=W, pady=4)
        ttk.Entry(frm, textvariable=self.pass2, show="•").grid(row=3, column=1, sticky=EW, padx=6)

        btns = ttk.Frame(frm); btns.grid(row=4, column=0, columnspan=2, pady=8)
        ttk.Button(btns, text="Criar", bootstyle=SUCCESS, command=lambda:self.create(on_done)).pack(side=LEFT, padx=6)
        ttk.Button(btns, text="Cancelar", bootstyle=SECONDARY, command=self.destroy).pack(side=LEFT, padx=6)
        frm.columnconfigure(1, weight=1)

    def create(self, on_done):
        badge = self.badge.get().strip()
        name  = self.name.get().strip()
        p1    = self.pass1.get()
        p2    = self.pass2.get()
        if not badge or not name or not p1:
            messagebox.showwarning("Campos", "Preencha crachá, nome e senha.")
            return
        if len(p1) < 8:
            messagebox.showwarning("Senha", "Use pelo menos 8 caracteres.")
            return
        if p1 != p2:
            messagebox.showwarning("Senha", "As senhas não coincidem.")
            return

        users = load_json_safe(USERS_FILE, {"version":1, "users":[]})
        users["users"].append({
            "badge_id": badge,
            "name": name,
            "role": "admin",
            "password": scrypt_hash(p1),
            "active": True
        })
        save_json(USERS_FILE, users)
        jl_append(LOG_FILE, {"ts": now_iso(), "type":"bootstrap_admin", "badge_id": badge})
        self.grab_release()
        self.destroy()
        on_done()

class LoginFrame(ttk.Frame):
    def __init__(self, master, on_success):
        super().__init__(master, padding=20)
        self.on_success = on_success
        self.badge = tk.StringVar()
        self.password = tk.StringVar()

        ttk.Label(self, text="Login", font=("-size", 16)).pack(pady=(0,12))
        form = ttk.Frame(self); form.pack(fill=X)

        ttk.Label(form, text="Crachá:").grid(row=0, column=0, sticky=W, pady=6)
        ttk.Entry(form, textvariable=self.badge, width=32).grid(row=0, column=1, sticky=EW, padx=6)

        ttk.Label(form, text="Senha:").grid(row=1, column=0, sticky=W, pady=6)
        ttk.Entry(form, textvariable=self.password, show="•", width=32).grid(row=1, column=1, sticky=EW, padx=6)

        btns = ttk.Frame(self); btns.pack(pady=12)
        ttk.Button(btns, text="Entrar", bootstyle=SUCCESS, command=self.do_login).pack(side=LEFT, padx=6)
        ttk.Button(btns, text="Fechar", bootstyle=DANGER, command=self.quit).pack(side=LEFT, padx=6)

        form.columnconfigure(1, weight=1)
        self.pack(fill=BOTH, expand=YES)

    def do_login(self):
        badge = self.badge.get().strip(); pwd = self.password.get()
        user, _ = find_user(badge)
        if not user or not user.get("active", False):
            messagebox.showerror("Acesso negado", "Crachá não encontrado ou inativo.")
            jl_append(LOG_FILE, {"ts": now_iso(), "type":"login", "badge_id":badge, "result":"denied"})
            return
        if not scrypt_verify(pwd, user["password"]):
            messagebox.showerror("Acesso negado", "Senha incorreta.")
            jl_append(LOG_FILE, {"ts": now_iso(), "type":"login", "badge_id":badge, "result":"denied"})
            return
        jl_append(LOG_FILE, {"ts": now_iso(), "type":"login", "badge_id":badge, "result":"granted"})
        self.on_success(user)

class UsersAdmin(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.a_badge = tk.StringVar(); self.a_name = tk.StringVar()
        self.a_role = tk.StringVar(value="user")
        self.a_pass = tk.StringVar(); self.a_active = tk.BooleanVar(value=True)

        frm = ttk.Labelframe(self, text="Usuários", padding=12); frm.pack(fill=X)
        ttk.Label(frm, text="Crachá:").grid(row=0, column=0, sticky=W, pady=4)
        ttk.Entry(frm, textvariable=self.a_badge).grid(row=0, column=1, sticky=EW, padx=6)
        ttk.Label(frm, text="Nome:").grid(row=1, column=0, sticky=W, pady=4)
        ttk.Entry(frm, textvariable=self.a_name).grid(row=1, column=1, sticky=EW, padx=6)
        ttk.Label(frm, text="Papel:").grid(row=2, column=0, sticky=W, pady=4)
        ttk.Combobox(frm, textvariable=self.a_role, values=["admin","user"], state="readonly").grid(row=2, column=1, sticky=EW, padx=6)
        ttk.Label(frm, text="Senha (8+):").grid(row=3, column=0, sticky=W, pady=4)
        ttk.Entry(frm, textvariable=self.a_pass, show="•").grid(row=3, column=1, sticky=EW, padx=6)
        ttk.Checkbutton(frm, text="Ativo", variable=self.a_active, bootstyle=SUCCESS).grid(row=4, column=1, sticky=W, pady=4)

        btns = ttk.Frame(frm); btns.grid(row=5, column=0, columnspan=2, pady=8)
        ttk.Button(btns, text="Salvar/Atualizar", bootstyle=PRIMARY, command=self.save_user).pack(side=LEFT, padx=5)
        ttk.Button(btns, text="Deletar", bootstyle=DANGER, command=self.delete_user).pack(side=LEFT, padx=5)
        ttk.Button(btns, text="Limpar", bootstyle=SECONDARY, command=self.clear_form).pack(side=LEFT, padx=5)
        frm.columnconfigure(1, weight=1)

        self.grid = ttk.Treeview(self, columns=("badge","name","role","active"), show="headings", height=10, bootstyle=INFO)
        for c,t in zip(("badge","name","role","active"),("Crachá","Nome","Papel","Ativo")):
            self.grid.heading(c, text=t); self.grid.column(c, width=160 if c!="name" else 240)
        self.grid.pack(fill=BOTH, expand=YES, pady=8)
        self.grid.bind("<<TreeviewSelect>>", self.on_select)
        self.refresh()

    def refresh(self):
        for i in self.grid.get_children(): self.grid.delete(i)
        data = load_json_safe(USERS_FILE, {"version":1, "users":[]})
        for u in data["users"]:
            self.grid.insert("", END, values=(u["badge_id"], u["name"], u["role"], "Sim" if u.get("active") else "Não"))

    def clear_form(self):
        self.a_badge.set(""); self.a_name.set(""); self.a_role.set("user"); self.a_pass.set(""); self.a_active.set(True)

    def on_select(self, _):
        sel = self.grid.selection()
        if not sel: return
        badge, name, role, active = self.grid.item(sel[0])["values"]
        self.a_badge.set(badge); self.a_name.set(name); self.a_role.set(role); self.a_active.set(active=="Sim"); self.a_pass.set("")

    def save_user(self):
        badge = self.a_badge.get().strip(); name = self.a_name.get().strip()
        role = self.a_role.get().strip(); pwd = self.a_pass.get(); active = bool(self.a_active.get())
        if not badge or not name:
            messagebox.showwarning("Campos", "Informe crachá e nome."); return
        data = load_json_safe(USERS_FILE, {"version":1, "users":[]})
        user = next((u for u in data["users"] if u["badge_id"] == badge), None)
        if user:
            user["name"]=name; user["role"]=role; user["active"]=active
            if pwd:
                if len(pwd) < 8: messagebox.showwarning("Senha", "8+ caracteres"); return
                user["password"]=scrypt_hash(pwd)
        else:
            if len(pwd) < 8: messagebox.showwarning("Senha", "8+ caracteres"); return
            data["users"].append({"badge_id":badge,"name":name,"role":role,"password":scrypt_hash(pwd),"active":active})
        save_json(USERS_FILE, data)
        jl_append(LOG_FILE, {"ts": now_iso(), "type":"user_save", "badge_id": badge})
        self.refresh(); self.clear_form()

    def delete_user(self):
        badge = self.a_badge.get().strip()
        if not badge: messagebox.showwarning("Seleção","Escolha um usuário."); return
        data = load_json_safe(USERS_FILE, {"version":1, "users":[]})
        data["users"] = [u for u in data["users"] if u["badge_id"] != badge]
        save_json(USERS_FILE, data)
        jl_append(LOG_FILE, {"ts": now_iso(), "type":"user_delete", "badge_id": badge})
        self.refresh(); self.clear_form()

class SubstancesView(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        top = ttk.Frame(self); top.pack(fill=X)
        ttk.Label(top, text="ID", bootstyle=PRIMARY).pack(side=LEFT, padx=6)
        ttk.Entry(top, bootstyle=PRIMARY).pack(side=LEFT, padx=6)
        ttk.Label(top, text="Nome", bootstyle=PRIMARY).pack(side=LEFT, padx=6)
        ttk.Entry(top, bootstyle=PRIMARY).pack(side=LEFT, padx=6)
        ttk.Label(top, text="data", bootstyle=PRIMARY).pack(side=LEFT, padx=6)
        ttk.Entry(top, bootstyle=PRIMARY).pack(side=LEFT, padx=6)
        ttk.Label(top, text="status", bootstyle=PRIMARY).pack(side=LEFT, padx=6)
        ttk.Entry(top, bootstyle=PRIMARY).pack(side=LEFT, padx=6)
        ttk.Button(top, text="Adicionar exemplo", bootstyle=SECONDARY, command=self.add_example).pack(side=LEFT)
        ttk.Button(top, text="Recarregar", bootstyle=PRIMARY, ).pack(side=LEFT, padx=6)
        
        self.grid = ttk.Treeview(self, columns=("id","Nome","Data","Status"), show="headings", bootstyle=INFO)
        for c,t in (("id","ID"),("Nome","Nome"),("Data","Data"),("Status","Status")):
            self.grid.heading(c, text=t); self.grid.column(c, width=150 if c!="name" else 240)
        self.grid.pack(fill=BOTH, expand=YES, pady=8)
        self.refresh()

    def refresh(self):
        self.grid = ttk.Treeview(self, columns=("id","Nome","Data","Status"), show="headings", bootstyle=INFO)
        for i in self.grid.get_children(): self.grid.delete(i)
        data = load_json_safe(SUBS_FILE, {"version":1, "substances":[]})
        for s in data["substances"]:
            self.grid.insert("", END, values=(s["id"], s["Nome"], s["Data"], s["Status"]))

    def add_example(self):
        self.grid = ttk.Treeview(self, columns=("id","Nome","Data","Status"), show="headings", bootstyle=INFO)
        data = load_json_safe(SUBS_FILE, {"version":1, "substances":[]})
        data["substances"].append({f"ID":"{id}","Nome":"{Nome}","Data:":"{Data}","Status":"{Status}"})
        save_json(SUBS_FILE, data)
        self.refresh()

class SamplesView(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.grid = ttk.Treeview(self, columns=("id","descrição","data","status"), show="headings", bootstyle=INFO)
        for c,t in (("id","ID"),("desc","Descrição"),("date","Data"),("status","Status")):
            self.grid.heading(c, text=t); self.grid.column(c, width=160 if c!="desc" else 320)
        self.grid.pack(fill=BOTH, expand=YES, pady=8)
        self.seed_if_empty(); self.refresh()

    def seed_if_empty(self):
        data = load_json_safe(SAMP_FILE, {"version":1, "samples":[]})
        if not data["samples"]:
            data["samples"] = [
                {"id":"A-0001","desc":"Amostra inicial pH água","date":datetime.date.today().isoformat(),"status":"Recebida"}
            ]
            save_json(SAMP_FILE, data)

    def refresh(self):
        for i in self.grid.get_children(): self.grid.delete(i)
        data = load_json_safe(SAMP_FILE, {"version":1, "samples":[]})
        for s in data["samples"]:
            self.grid.insert("", END, values=(s["id"], s["desc"], s["date"], s["status"]))

class MainApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("Controle de Acesso - Biotecnologia")
        self.geometry("1280x620")
        ensure_data_files()
        self.route()

    def route(self):
        # se não há usuários, força criação do primeiro admin
        users = load_json_safe(USERS_FILE, {"version":1, "users":[]})
        if len(users["users"]) == 0:
            def on_boot_done():
                for w in self.winfo_children(): w.destroy()
                self.show_login()
            FirstAdminDialog(self, on_done=on_boot_done)
        else:
            self.show_login()

    def clear_root(self):
        for w in self.winfo_children(): w.destroy()

    def show_login(self):
        self.clear_root()
        LoginFrame(self, on_success=self.after_login)

    def after_login(self, user):
        self.clear_root()
        nb = ttk.Notebook(self); nb.pack(fill=BOTH, expand=YES, padx=10, pady=10)
        if user["role"] == "admin":
            nb.add(SubstancesView(nb), text="Substâncias")
            nb.add(UsersAdmin(nb), text="Usuários")
        else:
            nb.add(SamplesView(nb), text="Amostras")
        bar = ttk.Frame(self); bar.pack(fill=X, padx=10, pady=(0,10))
        ttk.Label(bar, text=f"Logado: {user['name']} ({user['role']})").pack(side=LEFT)
        ttk.Button(bar, text="Sair", bootstyle=DANGER, command=self.show_login).pack(side=RIGHT)

if __name__ == "__main__":
    MainApp().mainloop()
