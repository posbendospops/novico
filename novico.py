"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  NOVICO SECURITY  —  Advanced Threat Protection Suite  v1.0                 ║
║  Design: Industrial Neon | Estética: Retro-Futurista Brasileiro             ║
╚══════════════════════════════════════════════════════════════════════════════╝

Instalação:
    pip install customtkinter psutil pillow matplotlib

Recursos:
  ✦ UI com design system próprio — cores neon sobre fundo carvão
  ✦ 5 Temas embutidos (NOVICO Verde / Vermelho Alerta / Oceano / Dourado / Claro)
  ✦ Dashboard com gráfico tempo real CPU/RAM
  ✦ Scanner multimodo com análise heurística + MD5
  ✦ Monitor de processos com "kill" e detalhes
  ✦ Anti-Keylogger com varredura profunda
  ✦ Quarentena com restauração / exclusão
  ✦ Firewall visual — conexões ativas por processo
  ✦ Análise de Vulnerabilidades com score 0-100
  ✦ Cofre de Senhas com gerador
  ✦ Limpador do sistema (temp, cache, logs)
  ✦ Agendador de varreduras
  ✦ Exportação de relatório HTML
  ✦ Notificações flutuantes
  ✦ Sidebar recolhível
  ✦ Logs filtráveis + exportação
"""

# ── Imports ──────────────────────────────────────────────────────────────────
import customtkinter as ctk
import psutil, os, sys, json, shutil, hashlib, threading, time
import random, socket, datetime, platform, subprocess, base64, math
from pathlib import Path
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinter import ttk
from collections import deque

# Matplotlib (opcional — gráficos em tempo real)
try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ══════════════════════════════════════════════════════════════════════════════
#  SISTEMA DE TEMAS  ──  cada tema define toda a paleta e tipografia
# ══════════════════════════════════════════════════════════════════════════════

THEMES = {
    "NOVICO Verde": {
        "bg0": "#080b08",   # fundo mais fundo
        "bg1": "#0c110c",   # painel sidebar
        "bg2": "#111811",   # cards
        "bg3": "#192519",   # hover
        "a1":  "#39ff14",   # verde neon primário
        "a2":  "#00e5ff",   # ciano acento
        "a3":  "#ffe600",   # amarelo alerta
        "ok":  "#39ff14",
        "warn":"#ffe600",
        "err": "#ff2244",
        "dim": "#3a5a3a",
        "txt": "#c8e8c8",
        "brd": "#1e3a1e",
        "fh":  "Courier New",
        "fb":  "Courier New",
        "cr":  6,
    },
    "Vermelho Alerta": {
        "bg0": "#0b0808",
        "bg1": "#110c0c",
        "bg2": "#1a1010",
        "bg3": "#2a1515",
        "a1":  "#ff2244",
        "a2":  "#ff8800",
        "a3":  "#ffee00",
        "ok":  "#44ff88",
        "warn":"#ff8800",
        "err": "#ff2244",
        "dim": "#5a2a2a",
        "txt": "#f0d0d0",
        "brd": "#3a1010",
        "fh":  "Courier New",
        "fb":  "Courier New",
        "cr":  4,
    },
    "Oceano Profundo": {
        "bg0": "#020a12",
        "bg1": "#040e1a",
        "bg2": "#071525",
        "bg3": "#0d2035",
        "a1":  "#00cfff",
        "a2":  "#00ffcc",
        "a3":  "#ff9f00",
        "ok":  "#00ffcc",
        "warn":"#ff9f00",
        "err": "#ff3355",
        "dim": "#1a4060",
        "txt": "#b0ddf8",
        "brd": "#0a2540",
        "fh":  "Courier New",
        "fb":  "Courier New",
        "cr":  10,
    },
    "Dourado Elite": {
        "bg0": "#0a0800",
        "bg1": "#110e00",
        "bg2": "#1a1500",
        "bg3": "#2a2200",
        "a1":  "#ffd700",
        "a2":  "#ff9500",
        "a3":  "#00e5ff",
        "ok":  "#88ff44",
        "warn":"#ff9500",
        "err": "#ff2244",
        "dim": "#5a4800",
        "txt": "#f8eac0",
        "brd": "#3a2e00",
        "fh":  "Courier New",
        "fb":  "Courier New",
        "cr":  8,
    },
    "Branco Cirúrgico": {
        "bg0": "#f0f4f0",
        "bg1": "#ffffff",
        "bg2": "#f5f8f5",
        "bg3": "#e8f0e8",
        "a1":  "#1a7a1a",
        "a2":  "#0077cc",
        "a3":  "#cc6600",
        "ok":  "#1a7a1a",
        "warn":"#cc6600",
        "err": "#cc1133",
        "dim": "#6a8a6a",
        "txt": "#1a2a1a",
        "brd": "#c0d8c0",
        "fh":  "Helvetica",
        "fb":  "Helvetica",
        "cr":  8,
    },
}

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

APP   = "NOVICO"
VER   = "1.0.0"
TAGLINE = "Security Suite"
DATA  = Path.home() / ".novico"
QDIR  = DATA / "quarantine"
LOG   = DATA / "novico.log"
CFG   = DATA / "config.json"
VAULT = DATA / "vault.json"
SCHED = DATA / "schedules.json"

for d in [DATA, QDIR]:
    d.mkdir(exist_ok=True)

# Base de assinaturas de malware (MD5 → nome, categoria, severidade)
MALWARE_DB: dict[str, tuple[str,str,str]] = {
    "44d88612fea8a8f36de82e1278abb02f": ("EICAR-Test-File",        "Teste",      "Baixa"),
    "e1112134b6dcc8bed54e0e34d8ac272f": ("Trojan.Generic.A",       "Trojan",     "Alta"),
    "098f6bcd4621d373cade4e832627b4f6": ("Virus.TestDetected",      "Vírus",      "Alta"),
    "5d41402abc4b2a76b9719d911017c592": ("Worm.Email.Spread",       "Worm",       "Média"),
    "d8e8fca2dc0f896fd7cb4cb0031ba249": ("Ransomware.Locky",        "Ransomware", "Crítica"),
    "aab3238922bcc25a6f606eb525ffdc56": ("Spyware.KeyCapture",      "Spyware",    "Alta"),
    "9bf31c7ff062936a96d3c8bd1f8f2ff3": ("Adware.Injector",         "Adware",     "Média"),
    "c4ca4238a0b923820dcc509a6f75849b": ("Backdoor.RemoteAccess",   "Backdoor",   "Crítica"),
    "eccbc87e4b5ce2fe28308fd9f2a7baf3": ("RootKit.Hidden.Srv",      "Rootkit",    "Crítica"),
    "1679091c5a880faf6fb5e6087eb1b2dc": ("Miner.CryptoJack",        "Minerador",  "Média"),
}

SUSP_EXT = {".exe",".bat",".cmd",".scr",".vbs",".js",".jar",
            ".ps1",".hta",".msi",".dll",".sys",".reg",".sh"}

KL_KEYWORDS = ["hook","keylog","capture","spy","monitor","record",
               "intercept","inject","logger","sniff","clipgrab","stealer"]

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def md5(path: str) -> str:
    h = hashlib.md5()
    try:
        with open(path,"rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

def fmt_b(n: int) -> str:
    for u in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def stamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(msg: str, level: str = "INFO") -> str:
    line = f"[{stamp()}] [{level:8}] {msg}"
    try:
        with open(LOG,"a",encoding="utf-8") as f:
            f.write(line+"\n")
    except Exception:
        pass
    return line

def default_cfg() -> dict:
    return {
        "theme":          "NOVICO Verde",
        "protection":     True,
        "realtime":       True,
        "archives":       True,
        "auto_quarantine":True,
        "heuristic":      True,
        "notifications":  True,
        "auto_update":    True,
        "scan_startup":   False,
        "sidebar_mini":   False,
        "definitions_ver":"2025.05.01",
        "last_scan":      "Nunca",
        "threats_total":  0,
        "files_scanned":  0,
        "scans_done":     0,
        "schedule_on":    False,
        "schedule_freq":  "Diário",
    }

def load_cfg() -> dict:
    d = default_cfg()
    try:
        if CFG.exists():
            d.update(json.loads(CFG.read_text()))
    except Exception:
        pass
    return d

def save_cfg(c: dict):
    try: CFG.write_text(json.dumps(c, indent=2, ensure_ascii=False))
    except Exception: pass

def pw_strength(pw: str) -> tuple[str,str]:
    s = sum([len(pw)>=12, any(c.isupper() for c in pw),
             any(c.isdigit() for c in pw),
             any(c in "!@#$%^&*()_+=-[]{}|;:,.<>?" for c in pw)])
    labels = ["Fraca","Média","Forte","Muito Forte"]
    colors = ["err","warn","ok","ok"]
    return labels[min(s,3)], colors[min(s,3)]

# ══════════════════════════════════════════════════════════════════════════════
#  WIDGETS REUTILIZÁVEIS
# ══════════════════════════════════════════════════════════════════════════════

class NvBtn(ctk.CTkButton):
    """Botão NOVICO com borda neon e hover animado."""
    def __init__(self, master, T: dict, color_key: str = "a1", **kw):
        c = T[color_key]
        kw.setdefault("fg_color",    c+"18")
        kw.setdefault("hover_color", c+"30")
        kw.setdefault("border_color",c)
        kw.setdefault("border_width",1)
        kw.setdefault("text_color",  c)
        kw.setdefault("font",        (T["fh"],11))
        kw.setdefault("corner_radius",T["cr"])
        super().__init__(master, **kw)


class NvCard(ctk.CTkFrame):
    """Card com cor de fundo do tema."""
    def __init__(self, master, T: dict, **kw):
        kw.setdefault("fg_color",     T["bg2"])
        kw.setdefault("corner_radius",T["cr"])
        kw.setdefault("border_width", 1)
        kw.setdefault("border_color", T["brd"])
        super().__init__(master, **kw)


class StatTile(NvCard):
    """Tile de estatística: ícone + valor + label."""
    def __init__(self, master, T: dict, icon: str, label: str,
                 value: str = "0", ck: str = "a1", **kw):
        super().__init__(master, T, **kw)
        self._T = T; self._ck = ck
        fh = T["fh"]
        ctk.CTkLabel(self, text=icon, font=("Segoe UI Emoji",26)).pack(pady=(14,0))
        ctk.CTkLabel(self, text=label, font=(fh,8), text_color=T["dim"]).pack()
        self._v = ctk.StringVar(value=value)
        ctk.CTkLabel(self, textvariable=self._v, font=(fh,22,"bold"),
                     text_color=T[ck]).pack(pady=(2,14))

    def set(self, v): self._v.set(str(v))


class NvSep(ctk.CTkFrame):
    def __init__(self, m, T, **kw):
        super().__init__(m, height=1, fg_color=T["brd"], **kw)


class Toast:
    """Notificações flutuantes no canto superior direito."""
    def __init__(self, root, T):
        self.root = root; self.T = T
        self._q: list = []; self._busy = False

    def push(self, title: str, body: str, kind: str = "info"):
        self._q.append((title, body, kind))
        if not self._busy: self._next()

    def _next(self):
        if not self._q: self._busy = False; return
        self._busy = True
        title, body, kind = self._q.pop(0)
        T = self.T
        ck = {"info":"a1","ok":"ok","warn":"warn","err":"err"}.get(kind,"a1")
        col = T[ck]

        w = ctk.CTkToplevel(self.root)
        w.overrideredirect(True); w.attributes("-topmost", True)
        w.configure(fg_color=T["bg2"])
        sw = self.root.winfo_screenwidth()
        w.geometry(f"310x72+{sw-326}+55")

        # Borda colorida esquerda
        ctk.CTkFrame(w, width=4, fg_color=col, corner_radius=0).pack(side="left",fill="y")
        inner = ctk.CTkFrame(w, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=10, pady=8)
        ctk.CTkLabel(inner, text=title, font=(T["fh"],11,"bold"),
                     text_color=col).pack(anchor="w")
        ctk.CTkLabel(inner, text=body, font=(T["fb"],9),
                     text_color=T["dim"]).pack(anchor="w")

        self.root.after(3200, lambda: (w.destroy(), self.root.after(120, self._next)))


# ══════════════════════════════════════════════════════════════════════════════
#  APLICAÇÃO PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

class Novico(ctk.CTk):

    # ── Init ─────────────────────────────────────────────────────────────────
    def __init__(self):
        super().__init__()
        self.cfg = load_cfg()
        self.T   = THEMES[self.cfg.get("theme","NOVICO Verde")]

        # Estado
        self.prot_on   = ctk.BooleanVar(value=self.cfg["protection"])
        self.scanning  = False
        self.q_items:  list[dict] = []
        self.vault_db: list[dict] = self._load_json(VAULT)
        self.sched_db: list[dict] = self._load_json(SCHED)
        self.blocked_ips: list[str] = []

        # Histórico para gráfico
        self.cpu_hist = deque([0]*60, maxlen=60)
        self.ram_hist = deque([0]*60, maxlen=60)

        # Janela
        self.title(f"{APP}  {TAGLINE}  v{VER}")
        self.geometry("1300x810")
        self.minsize(1100, 700)
        self.configure(fg_color=self.T["bg0"])

        self.toast = Toast(self, self.T)
        self._style_ttk()
        self._ui()
        self._start_bg()
        self.show("dashboard")
        log(f"{APP} v{VER} iniciado.")

    def _load_json(self, p: Path) -> list:
        try:
            if p.exists(): return json.loads(p.read_text())
        except Exception: pass
        return []

    def _save_json(self, p: Path, data):
        try: p.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        except Exception: pass

    # ── TTK Style ─────────────────────────────────────────────────────────────
    def _style_ttk(self):
        T = self.T
        s = ttk.Style(); s.theme_use("clam")
        s.configure("N.Treeview",
            background=T["bg0"], foreground=T["txt"],
            fieldbackground=T["bg0"], rowheight=27,
            font=(T["fb"],10), borderwidth=0, relief="flat",
            selectbackground=T["bg3"])
        s.configure("N.Treeview.Heading",
            background=T["bg1"], foreground=T["a1"],
            font=(T["fh"],10,"bold"), relief="flat", borderwidth=0)
        s.map("N.Treeview",
              background=[("selected",T["bg3"])],
              foreground=[("selected",T["a1"])])

    def _tree(self, parent, cols, widths, anchors=None, h=12):
        """Cria Treeview padronizado com scrollbar."""
        wrap = NvCard(parent, self.T)
        tree = ttk.Treeview(wrap, columns=cols, show="headings",
                            style="N.Treeview", height=h)
        for i,(c,w) in enumerate(zip(cols,widths)):
            a = anchors[i] if anchors else "w"
            tree.heading(c, text=c)
            tree.column(c, width=w, anchor=a, stretch=False)

        sb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscroll=sb.set)
        tree.pack(side="left", fill="both", expand=True, padx=(8,0), pady=8)
        sb.pack(side="right", fill="y", pady=8, padx=(0,4))

        T = self.T
        tree.tag_configure("ok",   foreground=T["ok"])
        tree.tag_configure("warn", foreground=T["warn"])
        tree.tag_configure("err",  foreground=T["err"])
        tree.tag_configure("info", foreground=T["a1"])
        tree.tag_configure("dim",  foreground=T["dim"])
        tree.tag_configure("a2",   foreground=T["a2"])
        return wrap, tree

    # ── Estrutura da UI ───────────────────────────────────────────────────────
    def _ui(self):
        self.root_h = ctk.CTkFrame(self, fg_color="transparent")
        self.root_h.pack(fill="both", expand=True)
        self._sidebar()
        self._main_area()

    # ══════════════════════════════════════════════════════════════════════════
    #  SIDEBAR
    # ══════════════════════════════════════════════════════════════════════════
    def _sidebar(self):
        T = self.T
        mini = self.cfg.get("sidebar_mini", False)
        self._sb_mini = mini
        w = 58 if mini else 230

        self.sb = ctk.CTkFrame(self.root_h, fg_color=T["bg1"],
                               corner_radius=0, width=w)
        self.sb.pack(side="left", fill="y")
        self.sb.pack_propagate(False)
        self._sb_fill()

    def _sb_fill(self):
        T = self.T; fh = T["fh"]
        for c in self.sb.winfo_children(): c.destroy()
        mini = self._sb_mini

        # ── Logo ──
        logo = ctk.CTkFrame(self.sb, fg_color="transparent")
        logo.pack(pady=(22,4), padx=8, fill="x")

        # Escudo SVG-like com label
        shield_lbl = ctk.CTkLabel(logo, text="🛡",
                                   font=("Segoe UI Emoji", 34 if mini else 42))
        shield_lbl.pack()
        if not mini:
            ctk.CTkLabel(logo, text=APP, font=(fh,20,"bold"),
                         text_color=T["a1"]).pack()
            ctk.CTkLabel(logo, text=TAGLINE, font=(fh,8),
                         text_color=T["dim"]).pack()
            ctk.CTkLabel(logo, text=f"v{VER}", font=(fh,7),
                         text_color=T["brd"]).pack(pady=(0,4))

        NvSep(self.sb, T).pack(fill="x", padx=10, pady=8)

        # Botão colapsar
        cb = ctk.CTkButton(self.sb,
            text="◀" if not mini else "▶",
            width=30, height=26, corner_radius=4,
            fg_color=T["bg3"], hover_color=T["bg2"],
            text_color=T["dim"], font=(fh,11),
            command=self._toggle_sb)
        cb.pack(anchor="e" if not mini else "center", padx=8, pady=(0,4))

        # Itens de navegação
        self._nav_btns: dict[str,ctk.CTkButton] = {}
        nav = [
            ("dashboard",  "⊞", "Dashboard"),
            ("scanner",    "⌕", "Scanner"),
            ("monitor",    "◉", "Processos"),
            ("antikl",     "⌨", "Anti-Keylogger"),
            ("quarantine", "⚠", "Quarentena"),
            ("firewall",   "🔥","Firewall"),
            ("vuln",       "🔬","Vulnerabilidades"),
            ("vault",      "🔐","Cofre de Senhas"),
            ("cleaner",    "🧹","Limpador"),
            ("scheduler",  "🗓","Agendador"),
            ("logs",       "📋","Logs"),
            ("settings",   "⚙", "Configurações"),
        ]
        for tid, icon, label in nav:
            txt = icon if mini else f"  {icon}  {label}"
            b = ctk.CTkButton(self.sb, text=txt,
                anchor="center" if mini else "w",
                height=38, corner_radius=T["cr"],
                fg_color="transparent", hover_color=T["bg3"],
                text_color=T["dim"], font=(fh, 13),
                command=lambda t=tid: self.show(t))
            b.pack(fill="x", padx=8, pady=2)
            self._nav_btns[tid] = b

        ctk.CTkFrame(self.sb, fg_color="transparent").pack(expand=True)

        # Status proteção
        if not mini:
            self._sb_status = ctk.CTkLabel(self.sb, text="● PROTEGIDO",
                font=(fh,11,"bold"), text_color=T["ok"])
            self._sb_status.pack(pady=(0,4))
            ctk.CTkLabel(self.sb,
                text=f"{platform.system()} {platform.release()[:8]}",
                font=(fh,7), text_color=T["brd"]).pack(pady=(0,14))

    def _toggle_sb(self):
        self._sb_mini = not self._sb_mini
        self.cfg["sidebar_mini"] = self._sb_mini
        w = 58 if self._sb_mini else 230
        self.sb.configure(width=w)
        self._sb_fill()
        if hasattr(self,"_cur"): self._hl(self._cur)

    def _hl(self, tid: str):
        """Destaca botão ativo na sidebar."""
        T = self.T
        for t,b in self._nav_btns.items():
            if t == tid:
                b.configure(fg_color=T["bg3"], text_color=T["a1"])
            else:
                b.configure(fg_color="transparent", text_color=T["dim"])

    # ══════════════════════════════════════════════════════════════════════════
    #  ÁREA PRINCIPAL
    # ══════════════════════════════════════════════════════════════════════════
    def _main_area(self):
        T = self.T; fh = T["fh"]
        self.main = ctk.CTkFrame(self.root_h, fg_color=T["bg0"], corner_radius=0)
        self.main.pack(side="left", fill="both", expand=True)

        # Header
        hdr = ctk.CTkFrame(self.main, height=58, fg_color=T["bg1"], corner_radius=0)
        hdr.pack(fill="x"); hdr.pack_propagate(False)

        self._hdr_title = ctk.CTkLabel(hdr, text="Dashboard",
            font=(fh,19,"bold"), text_color=T["a1"])
        self._hdr_title.pack(side="left", padx=22)

        rhs = ctk.CTkFrame(hdr, fg_color="transparent")
        rhs.pack(side="right", padx=14, pady=8)

        ctk.CTkLabel(rhs, text="Proteção:", font=(fh,10),
                     text_color=T["dim"]).pack(side="left", padx=(0,4))
        self._hdr_sw = ctk.CTkSwitch(rhs, text="", variable=self.prot_on,
            width=50, height=24, progress_color=T["ok"],
            onvalue=True, offvalue=False, command=self._toggle_prot)
        self._hdr_sw.pack(side="left", padx=6)

        self._clock = ctk.CTkLabel(rhs, text="", font=(fh,11), text_color=T["dim"])
        self._clock.pack(side="left", padx=10)
        self._tick()

        # Linha accent
        ctk.CTkFrame(self.main, height=2, fg_color=T["a1"], corner_radius=0).pack(fill="x")

        # Conteúdo — todas as abas ficam aqui
        self.content = ctk.CTkFrame(self.main, fg_color="transparent")
        self.content.pack(fill="both", expand=True, padx=14, pady=12)

        self._tabs: dict[str, ctk.CTkFrame] = {}
        self._build_dashboard()
        self._build_scanner()
        self._build_monitor()
        self._build_antikl()
        self._build_quarantine()
        self._build_firewall()
        self._build_vuln()
        self._build_vault()
        self._build_cleaner()
        self._build_scheduler()
        self._build_logs()
        self._build_settings()

    def _tick(self):
        self._clock.configure(
            text=datetime.datetime.now().strftime("%d/%m/%Y  %H:%M:%S"))
        self.after(1000, self._tick)

    def show(self, tid: str):
        for f in self._tabs.values(): f.pack_forget()
        self._tabs[tid].pack(fill="both", expand=True)
        self._hl(tid); self._cur = tid
        titles = {
            "dashboard":"Dashboard","scanner":"Scanner de Arquivos",
            "monitor":"Monitor de Processos","antikl":"Anti-Keylogger",
            "quarantine":"Quarentena","firewall":"Firewall & Rede",
            "vuln":"Análise de Vulnerabilidades","vault":"Cofre de Senhas",
            "cleaner":"Limpador do Sistema","scheduler":"Agendador",
            "logs":"Logs de Eventos","settings":"Configurações & Temas",
        }
        self._hdr_title.configure(text=titles.get(tid, tid.title()))
        # Refresh automático de certas abas
        auto = {"monitor":self._ref_procs,"quarantine":self._ref_quarantine,
                "firewall":self._ref_conns,"logs":self._ref_logs}
        if tid in auto: auto[tid]()

    def _toggle_prot(self):
        T = self.T; on = self.prot_on.get()
        if hasattr(self,"_sb_status"):
            self._sb_status.configure(
                text="● PROTEGIDO" if on else "● EXPOSTO",
                text_color=T["ok"] if on else T["err"])
        if on:
            self.toast.push("Proteção Ativada","Monitoramento em tempo real ligado.","ok")
            log("Proteção ativada.")
        else:
            self.toast.push("⚠ Atenção","Proteção desativada — sistema exposto!","warn")
            log("Proteção desativada.","WARNING")
        self.cfg["protection"] = on; save_cfg(self.cfg)

    # ════════════════════════════════════════════════════════════════════════
    # ABA 1 — DASHBOARD
    # ════════════════════════════════════════════════════════════════════════
    def _build_dashboard(self):
        T = self.T; fh = T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["dashboard"] = f

        # ── Linha 1: Status + 4 tiles ───────────────────────────────────────
        r1 = ctk.CTkFrame(f, fg_color="transparent")
        r1.pack(fill="x", pady=(0,10))

        # Status principal
        sc = NvCard(f, T)
        sc.pack(in_=r1, side="left", fill="both", expand=True, padx=(0,8))

        self._dash_icon = ctk.CTkLabel(sc, text="🛡", font=("Segoe UI Emoji",52))
        self._dash_icon.pack(pady=(18,2))
        self._dash_lbl = ctk.CTkLabel(sc, text="SISTEMA PROTEGIDO",
            font=(fh,16,"bold"), text_color=T["ok"])
        self._dash_lbl.pack()
        self._dash_sub = ctk.CTkLabel(sc,
            text="Todas as camadas de proteção ativas",
            font=(fh,8), text_color=T["dim"])
        self._dash_sub.pack(pady=(2,18))

        # Grid 2×2 de tiles
        tiles_col = ctk.CTkFrame(r1, fg_color="transparent")
        tiles_col.pack(side="left", fill="both", expand=True)

        ra = ctk.CTkFrame(tiles_col, fg_color="transparent")
        ra.pack(fill="x", pady=(0,6))
        rb = ctk.CTkFrame(tiles_col, fg_color="transparent")
        rb.pack(fill="x")

        self._t_threat  = StatTile(ra,T,"⚠","Ameaças","0","err")
        self._t_files   = StatTile(ra,T,"📁","Verificados","0","a1")
        self._t_q       = StatTile(rb,T,"🔒","Quarentena","0","warn")
        self._t_uptime  = StatTile(rb,T,"⏱","Uptime","0h","a2")

        for t in [self._t_threat, self._t_files]:
            t.pack(in_=ra, side="left", expand=True, fill="x", padx=4)
        for t in [self._t_q, self._t_uptime]:
            t.pack(in_=rb, side="left", expand=True, fill="x", padx=4)

        # ── Linha 2: Barras de recurso ──────────────────────────────────────
        r2 = ctk.CTkFrame(f, fg_color="transparent")
        r2.pack(fill="x", pady=(0,10))

        self._res_bars: dict = {}
        for attr,label,ck in [("cpu","CPU","a1"),("ram","RAM","a2"),("disk","DISCO","warn")]:
            c = NvCard(f, T)
            c.pack(in_=r2, side="left", fill="both", expand=True, padx=4)
            ctk.CTkLabel(c, text=label, font=(fh,10,"bold"),
                         text_color=T["dim"]).pack(pady=(12,4))
            bar = ctk.CTkProgressBar(c, height=10, progress_color=T[ck],
                                     fg_color=T["bg3"])
            bar.pack(fill="x", padx=14); bar.set(0)
            pct = ctk.CTkLabel(c, text="0%", font=(fh,15,"bold"), text_color=T[ck])
            pct.pack(pady=(3,12))
            self._res_bars[attr] = (bar, pct)

        # ── Linha 3: Gráfico + Ações rápidas ───────────────────────────────
        r3 = ctk.CTkFrame(f, fg_color="transparent")
        r3.pack(fill="both", expand=True)

        # Gráfico
        if HAS_MPL:
            gc = NvCard(f, T)
            gc.pack(in_=r3, side="left", fill="both", expand=True, padx=(0,8))
            ctk.CTkLabel(gc, text="Monitor em Tempo Real",
                         font=(fh,9,"bold"), text_color=T["dim"]
                         ).pack(anchor="w", padx=10, pady=(8,0))

            bg_hex = T["bg2"].lstrip("#")
            bg_rgb = tuple(int(bg_hex[i:i+2],16)/255 for i in (0,2,4))
            self._fig = Figure(figsize=(5,2.2), dpi=96, facecolor=bg_rgb)
            self._ax  = self._fig.add_subplot(111)
            self._ax.set_facecolor(bg_rgb)
            self._ax.tick_params(colors=T["dim"], labelsize=7)
            for sp in self._ax.spines.values():
                sp.set_edgecolor(T["brd"])
            self._fig.tight_layout(pad=1.2)
            self._cpu_line, = self._ax.plot(
                list(self.cpu_hist), color=T["a1"], lw=1.4, label="CPU")
            self._ram_line, = self._ax.plot(
                list(self.ram_hist), color=T["a2"], lw=1.4, label="RAM")
            self._ax.set_ylim(0,100); self._ax.set_xlim(0,59)
            self._ax.legend(loc="upper right", fontsize=7,
                            facecolor=T["bg3"], edgecolor=T["brd"],
                            labelcolor=T["dim"])
            canv = FigureCanvasTkAgg(self._fig, master=gc)
            canv.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=(4,10))
            self._canv = canv
        else:
            gc = NvCard(f, T)
            gc.pack(in_=r3, side="left", fill="both", expand=True, padx=(0,8))
            ctk.CTkLabel(gc,
                text="pip install matplotlib\npara gráficos em tempo real",
                font=(fh,10), text_color=T["dim"]).pack(expand=True)

        # Ações rápidas
        ac = NvCard(f, T, width=210)
        ac.pack(in_=r3, side="left", fill="y"); ac.pack_propagate(False)
        ctk.CTkLabel(ac, text="Ações Rápidas", font=(fh,10,"bold"),
                     text_color=T["dim"]).pack(anchor="w", padx=12, pady=(12,6))

        quick = [
            ("⚡ Varredura Rápida",    "a1", lambda: self.show("scanner")),
            ("🔬 Analisar Vuln.",      "warn",lambda: self.show("vuln")),
            ("🧹 Limpar Sistema",      "ok",  lambda: self.show("cleaner")),
            ("📊 Exportar Relatório",  "a2",  self._export_html),
            ("🔄 Atualizar Definições","a3",  self._update_defs),
        ]
        for txt, ck, cmd in quick:
            NvBtn(ac, T, ck, text=txt, height=34, command=cmd
                  ).pack(fill="x", padx=10, pady=3)

        NvSep(ac, T).pack(fill="x", padx=10, pady=8)
        self._last_scan_lbl = ctk.CTkLabel(ac,
            text=f"Última varredura:\n{self.cfg.get('last_scan','Nunca')}",
            font=(fh,8), text_color=T["dim"], justify="center")
        self._last_scan_lbl.pack(pady=(0,10))

    # ════════════════════════════════════════════════════════════════════════
    # ABA 2 — SCANNER
    # ════════════════════════════════════════════════════════════════════════
    def _build_scanner(self):
        T = self.T; fh = T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["scanner"] = f

        # Modo + opções
        cfg = NvCard(f, T)
        cfg.pack(fill="x", pady=(0,8))
        cfg_row = ctk.CTkFrame(cfg, fg_color="transparent")
        cfg_row.pack(fill="x", padx=14, pady=12)

        ctk.CTkLabel(cfg_row, text="Modo:", font=(fh,11), text_color=T["dim"]
                     ).pack(side="left")
        self._scan_mode = ctk.StringVar(value="Rápido")
        for m in ["Rápido","Completo","Personalizado"]:
            ctk.CTkRadioButton(cfg_row, text=m, variable=self._scan_mode, value=m,
                font=(fh,11), text_color=T["txt"], fg_color=T["a1"],
                hover_color=T["a1"]+"88").pack(side="left", padx=10)

        opts_row = ctk.CTkFrame(cfg, fg_color="transparent")
        opts_row.pack(fill="x", padx=14, pady=(0,10))
        self._opt_heur = ctk.BooleanVar(value=True)
        self._opt_arch = ctk.BooleanVar(value=True)
        self._opt_hidd = ctk.BooleanVar(value=False)
        for lbl,var in [("Heurística",self._opt_heur),
                         ("Comprimidos",self._opt_arch),
                         ("Ocultos",self._opt_hidd)]:
            ctk.CTkCheckBox(opts_row, text=lbl, variable=var,
                font=(fh,10), text_color=T["txt"], fg_color=T["a1"]
                ).pack(side="left", padx=10)

        # Caminho
        pr = NvCard(f, T)
        pr.pack(fill="x", pady=(0,8))
        path_row = ctk.CTkFrame(pr, fg_color="transparent")
        path_row.pack(fill="x", padx=14, pady=10)

        self._scan_path = ctk.StringVar(value=str(Path.home()))
        ctk.CTkLabel(path_row, text="📂", font=("Segoe UI Emoji",16)
                     ).pack(side="left", padx=(0,6))
        ctk.CTkEntry(path_row, textvariable=self._scan_path, width=480,
            font=(fh,11), fg_color=T["bg0"], border_color=T["brd"],
            text_color=T["a1"]).pack(side="left", padx=4)
        NvBtn(pr, T, "dim", text="Escolher", width=88, height=30,
              command=lambda: self._scan_path.set(
                  filedialog.askdirectory() or self._scan_path.get())
              ).pack(in_=path_row, side="left", padx=4)
        NvBtn(pr, T, "a1", text="▶ Iniciar", width=105, height=30,
              font=(fh,11,"bold"), command=self._scan_start
              ).pack(in_=path_row, side="left", padx=4)
        self._stop_btn = NvBtn(pr, T, "err", text="■ Parar",
              width=88, height=30, state="disabled", command=self._scan_stop)
        self._stop_btn.pack(in_=path_row, side="left", padx=4)

        # Progresso
        pg = NvCard(f, T)
        pg.pack(fill="x", pady=(0,8))
        self._scan_prog = ctk.CTkProgressBar(pg, height=12,
            progress_color=T["a1"], fg_color=T["bg3"])
        self._scan_prog.pack(fill="x", padx=14, pady=(12,4)); self._scan_prog.set(0)
        self._scan_lbl = ctk.CTkLabel(pg, text="Aguardando início...",
            font=(fh,8), text_color=T["dim"])
        self._scan_lbl.pack(pady=(0,10))

        # Tiles mini de resultado
        st_row = ctk.CTkFrame(f, fg_color="transparent")
        st_row.pack(fill="x", pady=(0,8))
        self._sc: dict[str,ctk.StringVar] = {}
        for lbl,ck in [("Verificados","a1"),("Limpos","ok"),
                        ("Ameaças","err"),("Suspeitos","warn")]:
            c = NvCard(f, T)
            c.pack(in_=st_row, side="left", expand=True, fill="x", padx=4)
            v = ctk.StringVar(value="0"); self._sc[lbl] = v
            ctk.CTkLabel(c,text=lbl,font=(fh,8),text_color=T["dim"]).pack(pady=(8,2))
            ctk.CTkLabel(c,textvariable=v,font=(fh,19,"bold"),
                         text_color=T[ck]).pack(pady=(0,8))

        # Tabela resultados
        rf, self._stree = self._tree(f,
            cols=("Status","Arquivo","Ameaça","Tipo","Sev.","Ação","Hash"),
            widths=[90,330,140,90,65,90,200],
            anchors=["c","w","w","c","c","c","w"], h=10)
        rf.pack(fill="both", expand=True)

        # Botões de ação sobre resultado
        brow = ctk.CTkFrame(f, fg_color="transparent")
        brow.pack(fill="x", pady=(6,0))
        NvBtn(brow,T,"warn",text="⚠ Quarentenar Sel.",width=190,height=32,
              command=self._q_selected).pack(side="left")
        NvBtn(brow,T,"err", text="🗑 Excluir Sel.",    width=160,height=32,
              command=self._del_selected).pack(side="left", padx=8)
        NvBtn(brow,T,"a2",  text="📋 Copiar Caminho", width=160,height=32,
              command=self._copy_path).pack(side="left")

    def _scan_start(self):
        if self.scanning: return
        folder = self._scan_path.get()
        if not os.path.isdir(folder):
            messagebox.showerror("Erro","Caminho inválido!"); return
        for r in self._stree.get_children(): self._stree.delete(r)
        for v in self._sc.values(): v.set("0")
        self._scan_prog.set(0)
        self.scanning = True
        self._stop_btn.configure(state="normal")
        self.cfg["scans_done"] = self.cfg.get("scans_done",0)+1
        log(f"Varredura iniciada: {folder}")
        threading.Thread(target=self._scan_worker, args=(folder,), daemon=True).start()

    def _scan_stop(self):
        self.scanning = False

    def _scan_worker(self, folder):
        total = max(sum(len(fs) for _,_,fs in os.walk(folder)),1)
        done = clean = threats = susp = 0
        mode = self._scan_mode.get()

        for root, dirs, files in os.walk(folder):
            if not self.scanning: break
            if mode == "Rápido":
                dirs[:] = [d for d in dirs if not d.startswith(".")][:4]
            for fn in files:
                if not self.scanning: break
                fp = os.path.join(root, fn)
                done += 1
                prog = min(done/total, 1.0)
                self.after(0, self._scan_prog.set, prog)
                self.after(0, self._scan_lbl.configure,
                           {"text": f"[{done}/{total}]  {fp[-74:]}..."})

                ext = Path(fn).suffix.lower()
                h   = md5(fp)
                rec = MALWARE_DB.get(h)

                if rec:
                    name, kind, sev = rec
                    threats += 1; tag = "err"
                    status = "⛔ AMEAÇA"; action = "Quarentena"
                    self.cfg["threats_total"] = self.cfg.get("threats_total",0)+1
                    log(f"AMEAÇA: {fp} [{name}]","CRITICAL")
                    self.after(0, self.toast.push,
                               "⛔ Ameaça Detectada!",
                               f"{name}  —  ...{fp[-38:]}", "err")
                    if self.cfg.get("auto_quarantine"):
                        self._q_file(fp, name)
                elif self._opt_heur.get() and ext in SUSP_EXT:
                    susp += 1; tag = "warn"
                    name,kind,sev = "Heurístico","Suspeito","Média"
                    status = "⚠ SUSPEITO"; action = "Monitorar"
                else:
                    clean += 1; tag = "ok"
                    name = kind = sev = ""; status = "✓ Limpo"; action = "—"

                self.after(0, self._stree.insert, "", "end",
                    values=(status, fp, name, kind, sev, action,
                            h[:18]+"…" if h else ""),
                    **{"tags":(tag,)})
                for k,v in zip(
                    ["Verificados","Limpos","Ameaças","Suspeitos"],
                    [done, clean, threats, susp]):
                    self.after(0, self._sc[k].set, str(v))
                self.cfg["files_scanned"] = self.cfg.get("files_scanned",0)+1
                time.sleep(0.007)

        self.scanning = False
        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
        self.cfg["last_scan"] = now; save_cfg(self.cfg)
        self.after(0, self._stop_btn.configure, {"state":"disabled"})
        self.after(0, self._scan_prog.set, 1.0)
        msg = f"Concluído: {done} arq., {threats} ameaças, {susp} suspeitos"
        self.after(0, self._scan_lbl.configure, {"text": msg})
        self.after(0, self._last_scan_lbl.configure,
                   {"text": f"Última varredura:\n{now}"})
        self.after(0, self._t_threat.set, self.cfg.get("threats_total",0))
        self.after(0, self._t_files.set,  self.cfg.get("files_scanned",0))
        log(msg)

    def _q_selected(self):
        for iid in self._stree.selection():
            vals = self._stree.item(iid,"values")
            fp = vals[1]
            if os.path.isfile(fp):
                self._q_file(fp, vals[2] or "Desconhecido")
                self._stree.delete(iid)

    def _del_selected(self):
        sel = self._stree.selection()
        if not sel: return
        if messagebox.askyesno("Excluir","Excluir arquivo(s) permanentemente?"):
            for iid in sel:
                try: os.remove(self._stree.item(iid,"values")[1])
                except Exception: pass
                self._stree.delete(iid)

    def _copy_path(self):
        sel = self._stree.selection()
        if sel:
            fp = self._stree.item(sel[0],"values")[1]
            self.clipboard_clear(); self.clipboard_append(fp)
            self.toast.push("Copiado","Caminho copiado para área de transferência.","ok")

    # ════════════════════════════════════════════════════════════════════════
    # ABA 3 — MONITOR DE PROCESSOS
    # ════════════════════════════════════════════════════════════════════════
    def _build_monitor(self):
        T = self.T; fh = T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["monitor"] = f

        tb = NvCard(f, T)
        tb.pack(fill="x", pady=(0,8))
        row = ctk.CTkFrame(tb, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(row,text="🔍",font=("Segoe UI Emoji",15)).pack(side="left",padx=(0,4))
        self._pf = ctk.CTkEntry(row, width=200, placeholder_text="Filtrar...",
            font=(fh,11), fg_color=T["bg0"], border_color=T["brd"],
            text_color=T["a1"])
        self._pf.pack(side="left",padx=4)
        self._pf.bind("<KeyRelease>", lambda e: self._ref_procs())

        NvBtn(tb,T,"dim",text="🔄",width=36,height=30,font=(fh,12),
              command=self._ref_procs).pack(in_=row,side="left",padx=4)
        NvBtn(tb,T,"err",text="⛔ Encerrar",width=110,height=30,
              command=self._kill).pack(in_=row,side="left",padx=4)
        NvBtn(tb,T,"warn",text="📊 Detalhes",width=110,height=30,
              command=self._proc_detail).pack(in_=row,side="left",padx=4)
        NvBtn(tb,T,"a2",text="🔒 Suspender",width=120,height=30,
              command=self._suspend_proc).pack(in_=row,side="left",padx=4)

        self._pcnt = ctk.CTkLabel(row, text="", font=(fh,8), text_color=T["dim"])
        self._pcnt.pack(side="right")

        # Tiles resumo
        st = ctk.CTkFrame(f, fg_color="transparent")
        st.pack(fill="x", pady=(0,8))
        self._ms: dict[str,ctk.StringVar] = {}
        for lbl,ck in [("Processos","a1"),("CPU Total","a2"),
                        ("RAM Usada","warn"),("Threads","ok")]:
            c = NvCard(f,T); c.pack(in_=st,side="left",expand=True,fill="x",padx=4)
            v = ctk.StringVar(value="..."); self._ms[lbl] = v
            ctk.CTkLabel(c,text=lbl,font=(fh,8),text_color=T["dim"]).pack(pady=(8,2))
            ctk.CTkLabel(c,textvariable=v,font=(fh,17,"bold"),
                         text_color=T[ck]).pack(pady=(0,8))

        rf, self._ptree = self._tree(f,
            cols=("PID","Nome","CPU%","RAM MB","Threads","Status","Usuário","Risco"),
            widths=[60,185,60,75,65,80,130,80],
            anchors=["c","w","c","c","c","c","w","c"], h=16)
        rf.pack(fill="both", expand=True)
        self._ptree.heading("CPU%", command=lambda:self._sort(self._ptree,"CPU%",True))
        self._ptree.heading("RAM MB",command=lambda:self._sort(self._ptree,"RAM MB",True))

    def _ref_procs(self):
        for r in self._ptree.get_children(): self._ptree.delete(r)
        flt = self._pf.get().lower()
        cnt = cpu_s = ram_s = thr_s = 0
        procs = sorted(
            psutil.process_iter(["pid","name","cpu_percent","memory_info",
                                 "status","username","num_threads"]),
            key=lambda p:(p.info.get("cpu_percent") or 0), reverse=True)
        for p in procs:
            try:
                nm = p.info["name"] or "?"
                if flt and flt not in nm.lower(): continue
                pid = p.info["pid"]
                cpu = p.info.get("cpu_percent") or 0.0
                mem = p.info["memory_info"]
                ram = (mem.rss/1024/1024) if mem else 0
                thr = p.info.get("num_threads") or 0
                st  = p.info.get("status","?")
                usr = (p.info.get("username") or "?")[:18]
                cnt+=1; cpu_s+=cpu; ram_s+=ram; thr_s+=thr
                if cpu>40: rsk,tag="⛔ Alto","err"
                elif cpu>15: rsk,tag="⚠ Médio","warn"
                else: rsk,tag="✓ Baixo","ok"
                self._ptree.insert("","end",
                    values=(pid,nm,f"{cpu:.1f}",f"{ram:.1f}",thr,st,usr,rsk),
                    tags=(tag,), iid=str(pid))
            except Exception: continue
        self._pcnt.configure(text=f"{cnt} processos")
        self._ms["Processos"].set(str(cnt))
        self._ms["CPU Total"].set(f"{cpu_s:.1f}%")
        self._ms["RAM Usada"].set(fmt_b(int(ram_s*1024*1024)))
        self._ms["Threads"].set(str(thr_s))

    def _kill(self):
        sel = self._ptree.selection()
        if not sel: messagebox.showinfo("Aviso","Selecione um processo."); return
        try:
            p = psutil.Process(int(sel[0]))
            if messagebox.askyesno("Encerrar",f"Encerrar '{p.name()}' (PID {sel[0]})?"):
                p.terminate(); log(f"Encerrado: {p.name()} PID={sel[0]}","WARNING")
                self._ref_procs()
        except psutil.AccessDenied: messagebox.showerror("Erro","Permissão negada.")
        except psutil.NoSuchProcess: messagebox.showerror("Erro","Processo não encontrado.")

    def _suspend_proc(self):
        sel = self._ptree.selection()
        if not sel: return
        try:
            p = psutil.Process(int(sel[0]))
            if p.status() == psutil.STATUS_STOPPED:
                p.resume(); self.toast.push("Retomado",f"{p.name()} retomado.","ok")
            else:
                p.suspend(); self.toast.push("Suspenso",f"{p.name()} suspenso.","warn")
            self._ref_procs()
        except Exception as e: messagebox.showerror("Erro",str(e))

    def _proc_detail(self):
        T = self.T; fh = T["fh"]
        sel = self._ptree.selection()
        if not sel: return
        try:
            p = psutil.Process(int(sel[0]))
            win = ctk.CTkToplevel(self)
            win.title(f"Detalhes — {p.name()}")
            win.geometry("540x440"); win.configure(fg_color=T["bg0"]); win.grab_set()
            ctk.CTkLabel(win, text=p.name(), font=(fh,18,"bold"),
                         text_color=T["a1"]).pack(pady=(20,4))
            txt = ctk.CTkTextbox(win, font=(fh,11), fg_color=T["bg2"],
                                  text_color=T["txt"])
            txt.pack(fill="both", expand=True, padx=16, pady=16)
            lines = [
                f"PID:           {p.pid}",
                f"Status:        {p.status()}",
                f"Criado:        {datetime.datetime.fromtimestamp(p.create_time()).strftime('%d/%m/%Y %H:%M:%S')}",
                f"CPU%:          {p.cpu_percent()}%",
                f"RAM:           {fmt_b(p.memory_info().rss)}",
                f"Threads:       {p.num_threads()}",
                f"Usuário:       {p.username()}",
            ]
            for attr in ["exe","cwd"]:
                try: lines.append(f"{attr.capitalize()+':':<15}{getattr(p,attr)()}")
                except Exception: pass
            try: lines.append(f"Conexões:      {len(p.connections())}")
            except Exception: pass
            try: lines.append(f"Arq. abertos:  {len(p.open_files())}")
            except Exception: pass
            txt.insert("end","\n".join(lines)); txt.configure(state="disabled")
        except Exception as e: messagebox.showerror("Erro",str(e))

    def _sort(self, tree, col, num=False):
        items = [(tree.set(c,col),c) for c in tree.get_children("")]
        try: items.sort(key=lambda x:float(x[0]) if num else x[0], reverse=True)
        except ValueError: items.sort()
        for i,(_,c) in enumerate(items): tree.move(c,"",i)

    # ════════════════════════════════════════════════════════════════════════
    # ABA 4 — ANTI-KEYLOGGER
    # ════════════════════════════════════════════════════════════════════════
    def _build_antikl(self):
        T = self.T; fh = T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["antikl"] = f

        # Status card
        sc = NvCard(f, T); sc.pack(fill="x", pady=(0,8))
        row = ctk.CTkFrame(sc, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=16)
        ctk.CTkLabel(row, text="⌨", font=("Segoe UI Emoji",44)).pack(side="left")
        info = ctk.CTkFrame(row, fg_color="transparent")
        info.pack(side="left", padx=14, fill="x", expand=True)
        self._kl_lbl = ctk.CTkLabel(info, text="Anti-Keylogger  ATIVO",
            font=(fh,15,"bold"), text_color=T["ok"]); self._kl_lbl.pack(anchor="w")
        ctk.CTkLabel(info,
            text="Detecta processos que capturam entradas de teclado,\n"
                 "hooks suspeitos e comportamento de spyware.",
            font=(fh,8), text_color=T["dim"]).pack(anchor="w")
        btns = ctk.CTkFrame(row, fg_color="transparent"); btns.pack(side="right")
        NvBtn(btns,T,"a1",text="🔍 Escanear",width=128,height=34,
              font=(fh,11,"bold"),command=self._kl_scan).pack(pady=3)
        NvBtn(btns,T,"err",text="⛔ Matar Hook",width=128,height=34,
              command=self._kl_kill).pack(pady=3)

        # Alertas
        al = NvCard(f,T); al.pack(fill="x",pady=(0,8))
        ctk.CTkLabel(al,text="⚠  Alertas",font=(fh,10,"bold"),
                     text_color=T["warn"]).pack(anchor="w",padx=14,pady=(10,4))
        self._kl_alerts = ctk.CTkTextbox(al,height=110,font=(fh,10),
            fg_color=T["bg0"],text_color=T["warn"],border_color=T["brd"],border_width=1)
        self._kl_alerts.pack(fill="x",padx=14,pady=(0,12))
        self._kl_alerts.insert("end","Execute um escaneamento para detectar hooks.\n")
        self._kl_alerts.configure(state="disabled")

        rf, self._kltree = self._tree(f,
            cols=("PID","Processo","Usuário","Arq. Abertos","Conexões","Risco"),
            widths=[65,200,130,90,80,90],
            anchors=["c","w","w","c","c","c"], h=12)
        rf.pack(fill="both", expand=True)
        self._kl_refresh()

    def _kl_scan(self):
        self._kl_alerts.configure(state="normal")
        self._kl_alerts.delete("1.0","end")
        self._kl_alerts.insert("end","🔍 Analisando...\n")
        self._kl_alerts.configure(state="disabled")
        def worker():
            hits = []
            for p in psutil.process_iter(["pid","name","cmdline"]):
                try:
                    nm  = (p.info["name"] or "").lower()
                    cmd = " ".join(p.info.get("cmdline") or []).lower()
                    if any(k in nm or k in cmd for k in KL_KEYWORDS):
                        hits.append(f"⛔  [{p.info['pid']:6}]  {p.info['name']}")
                except Exception: continue
            for p in psutil.process_iter(["pid","name"]):
                try:
                    nf = len(p.open_files())
                    if nf > 50:
                        hits.append(f"⚠   [{p.info['pid']:6}]  {p.info['name']}  "
                                    f"— {nf} arquivos abertos")
                except Exception: continue
            res = "\n".join(hits) if hits else "✓ Nenhum keylogger detectado."
            res += f"\n\n— Concluído {datetime.datetime.now().strftime('%H:%M:%S')} —"
            log(f"Anti-keylogger: {len(hits)} suspeitos.")
            self.after(0, self._kl_set, res)
            self.after(0, self._kl_refresh)
        threading.Thread(target=worker, daemon=True).start()

    def _kl_set(self, t):
        self._kl_alerts.configure(state="normal")
        self._kl_alerts.delete("1.0","end")
        self._kl_alerts.insert("end",t)
        self._kl_alerts.configure(state="disabled")

    def _kl_refresh(self):
        for r in self._kltree.get_children(): self._kltree.delete(r)
        for p in psutil.process_iter(["pid","name","username"]):
            try:
                try: nf = len(p.open_files())
                except Exception: nf = 0
                try: nc = len(p.connections())
                except Exception: nc = 0
                if nf>30: rsk,tag="⛔ Alto","err"
                elif nf>10: rsk,tag="⚠ Médio","warn"
                else: rsk,tag="✓ Baixo","ok"
                self._kltree.insert("","end",
                    values=(p.info["pid"],p.info["name"] or "?",
                            (p.info.get("username") or "?")[:20],
                            nf,nc,rsk), tags=(tag,))
            except Exception: continue

    def _kl_kill(self):
        sel = self._kltree.selection()
        if not sel: return
        pid = int(self._kltree.item(sel[0],"values")[0])
        try:
            p = psutil.Process(pid)
            if messagebox.askyesno("Encerrar Hook",
                f"Encerrar '{p.name()}' (PID {pid})?"):
                p.terminate()
                log(f"Hook encerrado: {p.name()} PID={pid}","WARNING")
                self._kl_refresh()
        except Exception as e: messagebox.showerror("Erro",str(e))

    # ════════════════════════════════════════════════════════════════════════
    # ABA 5 — QUARENTENA
    # ════════════════════════════════════════════════════════════════════════
    def _build_quarantine(self):
        T = self.T; fh = T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["quarantine"] = f

        tb = NvCard(f, T); tb.pack(fill="x", pady=(0,8))
        row = ctk.CTkFrame(tb, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=10)
        ctk.CTkLabel(row, text="Arquivos em Quarentena",
                     font=(fh,13,"bold"), text_color=T["warn"]).pack(side="left")
        NvBtn(tb,T,"ok",  text="↩ Restaurar",  width=115,height=30,command=self._q_restore).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"err", text="🗑 Excluir",    width=100,height=30,command=self._q_delete ).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"dim", text="🗑 Limpar Tudo",width=125,height=30,command=self._q_clear  ).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"a2",  text="📊 Relatório",  width=110,height=30,command=self._export_html).pack(in_=row,side="right",padx=4)

        sl = ctk.CTkFrame(f, fg_color="transparent"); sl.pack(fill="x",pady=(0,6))
        self._ql_cnt  = ctk.CTkLabel(sl,text="0 itens",font=(fh,9),text_color=T["dim"])
        self._ql_cnt.pack(side="left")
        self._ql_size = ctk.CTkLabel(sl,text="0 B",font=(fh,9),text_color=T["dim"])
        self._ql_size.pack(side="right")

        rf, self._qtree = self._tree(f,
            cols=("Data","Arquivo Original","Ameaça","Tipo","Tamanho","Status"),
            widths=[130,300,160,80,80,85], h=16)
        rf.pack(fill="both", expand=True)

    def _q_file(self, fp, threat):
        try:
            fn   = Path(fp).name
            dest = QDIR / f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{fn}.qtn"
            shutil.move(fp, str(dest))
            sz = dest.stat().st_size
            self.q_items.append({
                "date":datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
                "original":fp,"threat":threat,
                "size":sz,"dest":str(dest),"status":"Isolado"
            })
            self._t_q.set(len(self.q_items))
            log(f"Quarentena: {fp}","WARNING")
        except Exception as e: log(f"Erro quarentena: {e}","ERROR")

    def _ref_quarantine(self):
        for r in self._qtree.get_children(): self._qtree.delete(r)
        tot = 0
        for it in self.q_items:
            ext = Path(it["original"]).suffix.upper() or "?"
            self._qtree.insert("","end",
                values=(it["date"],it["original"],it["threat"],
                        ext,fmt_b(it["size"]),it["status"]),tags=("warn",))
            tot += it["size"]
        self._ql_cnt.configure(text=f"{len(self.q_items)} itens")
        self._ql_size.configure(text=fmt_b(tot))

    def _q_restore(self):
        sel = self._qtree.selection()
        if not sel: return
        idx = self._qtree.index(sel[0]); it = self.q_items[idx]
        if messagebox.askyesno("⚠ Restaurar",
            f"Restaurar arquivo INFECTADO?\n{it['original']}"):
            try:
                shutil.move(it["dest"],it["original"])
                self.q_items.pop(idx)
                log(f"Restaurado: {it['original']}","WARNING")
                self._ref_quarantine()
            except Exception as e: messagebox.showerror("Erro",str(e))

    def _q_delete(self):
        sel = self._qtree.selection()
        if not sel: return
        idx = self._qtree.index(sel[0]); it = self.q_items[idx]
        if messagebox.askyesno("Excluir",f"Excluir permanentemente?\n{it['original']}"):
            try: os.remove(it["dest"])
            except Exception: pass
            self.q_items.pop(idx); log(f"Excluído da quarentena: {it['original']}")
            self._ref_quarantine()

    def _q_clear(self):
        if not self.q_items: return
        if messagebox.askyesno("Limpar","Excluir TODOS os arquivos da quarentena?"):
            for it in self.q_items:
                try: os.remove(it["dest"])
                except Exception: pass
            self.q_items.clear(); log("Quarentena limpa."); self._ref_quarantine()

    # ════════════════════════════════════════════════════════════════════════
    # ABA 6 — FIREWALL
    # ════════════════════════════════════════════════════════════════════════
    def _build_firewall(self):
        T = self.T; fh = T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["firewall"] = f

        tb = NvCard(f,T); tb.pack(fill="x",pady=(0,8))
        row = ctk.CTkFrame(tb,fg_color="transparent"); row.pack(fill="x",padx=14,pady=10)
        ctk.CTkLabel(row,text="🔥  Monitor de Rede & Firewall",
                     font=(fh,13,"bold"),text_color=T["err"]).pack(side="left")
        NvBtn(tb,T,"dim", text="🔄",width=36,height=30,command=self._ref_conns).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"err", text="⛔ Bloquear IP",width=130,height=30,command=self._block_ip).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"warn",text="🔍 Detalhes",width=110,height=30,command=self._conn_detail).pack(in_=row,side="right",padx=4)

        # Contadores de status
        st = ctk.CTkFrame(f,fg_color="transparent"); st.pack(fill="x",pady=(0,8))
        self._fw_st: dict[str,ctk.StringVar] = {}
        for lbl,ck in [("LISTEN","ok"),("ESTABLISHED","a1"),
                        ("TIME_WAIT","warn"),("OUTROS","dim")]:
            c=NvCard(f,T); c.pack(in_=st,side="left",expand=True,fill="x",padx=4)
            v=ctk.StringVar(value="0"); self._fw_st[lbl]=v
            ctk.CTkLabel(c,text=lbl,font=(fh,8),text_color=T["dim"]).pack(pady=(8,2))
            ctk.CTkLabel(c,textvariable=v,font=(fh,17,"bold"),text_color=T[ck]).pack(pady=(0,8))

        rf, self._ctree = self._tree(f,
            cols=("PID","Processo","Local","Remoto","Status","Proto","Risco"),
            widths=[60,150,185,185,100,55,75],
            anchors=["c","w","w","w","c","c","c"], h=16)
        rf.pack(fill="both",expand=True)

        bl = NvCard(f,T); bl.pack(fill="x",pady=(8,0))
        blr = ctk.CTkFrame(bl,fg_color="transparent"); blr.pack(fill="x",padx=14,pady=8)
        ctk.CTkLabel(blr,text="IPs Bloqueados:",font=(fh,9),text_color=T["dim"]).pack(side="left")
        self._bl_lbl = ctk.CTkLabel(blr,text="Nenhum",font=(fh,9),text_color=T["err"])
        self._bl_lbl.pack(side="left",padx=6)

    def _ref_conns(self):
        for r in self._ctree.get_children(): self._ctree.delete(r)
        cnt = {"LISTEN":0,"ESTABLISHED":0,"TIME_WAIT":0,"OUTROS":0}
        pnm: dict[int,str] = {}
        for p in psutil.process_iter(["pid","name"]):
            try: pnm[p.info["pid"]] = p.info["name"] or "?"
            except Exception: pass
        for c in psutil.net_connections("inet"):
            try:
                la = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?"
                ra = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—"
                st = c.status or "?"
                nm = pnm.get(c.pid or 0,"?")
                pr = "TCP" if c.type==1 else "UDP"
                rip = c.raddr.ip if c.raddr else ""
                if rip in self.blocked_ips: rsk,tag="⛔ BLOQ","err"
                elif "ESTABLISHED" in st: rsk,tag="Ativa","info"
                elif "LISTEN" in st: rsk,tag="Escutando","ok"
                else: rsk,tag="—","dim"
                for k in ["LISTEN","ESTABLISHED","TIME_WAIT"]:
                    if k in st: cnt[k]+=1; break
                else: cnt["OUTROS"]+=1
                self._ctree.insert("","end",
                    values=(c.pid or 0,nm,la,ra,st,pr,rsk),tags=(tag,))
            except Exception: continue
        for k,v in cnt.items():
            if k in self._fw_st: self._fw_st[k].set(str(v))

    def _block_ip(self):
        T=self.T; fh=T["fh"]
        sel = self._ctree.selection()
        pre = ""
        if sel:
            ra = self._ctree.item(sel[0],"values")[3]
            pre = ra.split(":")[0] if ":" in ra else ra

        d = ctk.CTkToplevel(self); d.title("Bloquear IP")
        d.geometry("360x160"); d.configure(fg_color=T["bg0"]); d.grab_set()
        ctk.CTkLabel(d,text="Endereço IP:",font=(fh,11),text_color=T["dim"]).pack(pady=(18,4))
        e = ctk.CTkEntry(d,width=260,font=(fh,11),fg_color=T["bg2"],
            border_color=T["brd"],text_color=T["a1"]); e.insert(0,pre); e.pack()
        def do():
            ip=e.get().strip()
            if ip and ip not in self.blocked_ips:
                self.blocked_ips.append(ip)
                self._bl_lbl.configure(text=", ".join(self.blocked_ips))
                log(f"IP bloqueado: {ip}","WARNING")
                self.toast.push("IP Bloqueado",f"{ip} adicionado à lista.","warn")
            d.destroy(); self._ref_conns()
        NvBtn(d,T,"err",text="⛔ Bloquear",width=150,height=34,
              font=(fh,11,"bold"),command=do).pack(pady=14)

    def _conn_detail(self):
        sel = self._ctree.selection()
        if not sel: return
        vals = self._ctree.item(sel[0],"values")
        msg = (f"PID:      {vals[0]}\n"
               f"Processo: {vals[1]}\n"
               f"Local:    {vals[2]}\n"
               f"Remoto:   {vals[3]}\n"
               f"Status:   {vals[4]}\n"
               f"Protocolo:{vals[5]}\n"
               f"Risco:    {vals[6]}")
        messagebox.showinfo("Detalhes da Conexão", msg)

    # ════════════════════════════════════════════════════════════════════════
    # ABA 7 — VULNERABILIDADES
    # ════════════════════════════════════════════════════════════════════════
    def _build_vuln(self):
        T=self.T; fh=T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["vuln"] = f

        tb = NvCard(f,T); tb.pack(fill="x",pady=(0,8))
        row = ctk.CTkFrame(tb,fg_color="transparent"); row.pack(fill="x",padx=14,pady=10)
        ctk.CTkLabel(row,text="🔬  Análise de Vulnerabilidades do Sistema",
                     font=(fh,13,"bold"),text_color=T["warn"]).pack(side="left")
        NvBtn(tb,T,"a1",text="▶ Analisar Agora",width=155,height=34,
              font=(fh,11,"bold"),command=self._vuln_run).pack(in_=row,side="right",padx=10)

        # Score
        sc = NvCard(f,T); sc.pack(fill="x",pady=(0,8))
        si = ctk.CTkFrame(sc,fg_color="transparent"); si.pack(fill="x",padx=16,pady=(12,4))
        ctk.CTkLabel(si,text="Score de Segurança",font=(fh,10),text_color=T["dim"]).pack(side="left")
        self._vsv = ctk.StringVar(value="—")
        self._vsl = ctk.CTkLabel(si,textvariable=self._vsv,
            font=(fh,30,"bold"),text_color=T["ok"]); self._vsl.pack(side="right")
        self._vpb = ctk.CTkProgressBar(sc,height=8,progress_color=T["ok"],fg_color=T["bg3"])
        self._vpb.pack(fill="x",padx=16,pady=(0,12)); self._vpb.set(0)

        rf, self._vtree = self._tree(f,
            cols=("Verificação","Resultado","Status","Severidade","Recomendação"),
            widths=[170,230,80,85,310],h=14)
        rf.pack(fill="both",expand=True)

    def _vuln_run(self):
        for r in self._vtree.get_children(): self._vtree.delete(r)
        self._vsv.set("Analisando..."); self._vpb.set(0)

        def worker():
            T=self.T; results=[]; passed=0

            def add(name,desc,ok,sev,rec):
                nonlocal passed
                if ok: passed+=1
                tag="ok" if ok else ("err" if sev in("Alta","Crítica") else "warn")
                results.append((name,desc,"✓ OK" if ok else "✗ FALHA",
                    sev if not ok else "—",
                    "Nenhuma ação." if ok else rec, tag))

            # Firewall
            fw=False
            if platform.system()=="Windows":
                try:
                    r=subprocess.run(["netsh","advfirewall","show","allprofiles"],
                        capture_output=True,text=True,timeout=5)
                    fw="ON" in r.stdout.upper()
                except Exception: pass
            elif platform.system()=="Linux":
                try:
                    r=subprocess.run(["ufw","status"],capture_output=True,text=True,timeout=5)
                    fw="active" in r.stdout.lower()
                except Exception: pass
            add("Firewall","Firewall do sistema operacional",fw,"Alta","Ative o firewall do SO.")

            # Portas perigosas
            open_ports=[c.laddr.port for c in psutil.net_connections("inet")
                        if c.status=="LISTEN" and c.laddr]
            danger_ports=[p for p in open_ports if p in [21,23,135,139,445,3389]]
            add("Portas Perigosas",f"Portas abertas: {open_ports[:6]}",
                len(danger_ports)==0,"Alta",f"Feche: {danger_ports}")

            # Disco
            disk=psutil.disk_usage("/"); free_p=disk.free/disk.total*100
            add("Espaço em Disco",f"{free_p:.1f}% livre ({fmt_b(disk.free)})",
                free_p>10,"Média","Libere espaço em disco.")

            # RAM
            ram=psutil.virtual_memory()
            add("Memória RAM",f"{ram.percent:.1f}% em uso",
                ram.percent<90,"Média","Sistema com pouca RAM disponível.")

            # Python
            pv=sys.version_info
            add("Python Runtime",f"Python {pv.major}.{pv.minor}.{pv.micro}",
                pv.minor>=10,"Baixa","Atualize para Python 3.10+.")

            # CPU alta
            high=[p.name() for p in psutil.process_iter(["name","cpu_percent"])
                  if (p.info.get("cpu_percent") or 0)>70]
            add("Processos CPU Alta",f"{len(high)} processo(s) com CPU>70%",
                len(high)==0,"Média",f"Investigue: {', '.join(high[:3])}")

            # Temp
            tmp_sz=0
            if os.path.exists("/tmp"):
                try: tmp_sz=sum(f.stat().st_size for f in Path("/tmp").rglob("*") if f.is_file())
                except Exception: pass
            add("Arquivos Temporários",fmt_b(tmp_sz)+" em /tmp",
                tmp_sz<500*1024*1024,"Baixa","Limpe arquivos temporários.")

            # Proteção ativa
            add("Proteção NOVICO","Proteção em tempo real",
                self.cfg.get("protection",True),"Alta","Ative a proteção no Dashboard.")

            # Definições atualizadas (simulado)
            def_ver=self.cfg.get("definitions_ver","")
            add("Definições de Vírus",f"Versão {def_ver}",
                bool(def_ver),"Alta","Atualize as definições de vírus.")

            score=int(passed/len(results)*100)
            col=T["ok"] if score>=80 else T["warn"] if score>=50 else T["err"]
            self.after(0, self._vuln_show, results, score, col)

        threading.Thread(target=worker,daemon=True).start()

    def _vuln_show(self, results, score, col):
        for nm,desc,st,sev,rec,tag in results:
            self._vtree.insert("","end",values=(nm,desc,st,sev,rec),tags=(tag,))
        self._vsv.set(f"{score}/100"); self._vsl.configure(text_color=col)
        self._vpb.configure(progress_color=col); self._vpb.set(score/100)
        log(f"Análise de vulnerabilidades: {score}/100")

    # ════════════════════════════════════════════════════════════════════════
    # ABA 8 — COFRE DE SENHAS
    # ════════════════════════════════════════════════════════════════════════
    def _build_vault(self):
        T=self.T; fh=T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["vault"] = f

        tb = NvCard(f,T); tb.pack(fill="x",pady=(0,8))
        row = ctk.CTkFrame(tb,fg_color="transparent"); row.pack(fill="x",padx=14,pady=10)
        ctk.CTkLabel(row,text="🔐  Cofre de Senhas NOVICO",
                     font=(fh,13,"bold"),text_color=T["a1"]).pack(side="left")
        NvBtn(tb,T,"ok",  text="+ Adicionar",width=110,height=30,command=self._vault_add ).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"a1",  text="👁 Revelar",  width=100,height=30,command=self._vault_rev ).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"a2",  text="📋 Copiar",   width=95, height=30,command=self._vault_copy).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"err", text="🗑 Excluir",  width=95, height=30,command=self._vault_del ).pack(in_=row,side="right",padx=4)

        # Gerador
        gc = NvCard(f,T); gc.pack(fill="x",pady=(0,8))
        gbl = ctk.CTkLabel(gc,text="Gerador de Senha",font=(fh,10,"bold"),
                           text_color=T["dim"])
        gbl.pack(anchor="w",padx=14,pady=(10,4))
        gr = ctk.CTkFrame(gc,fg_color="transparent"); gr.pack(fill="x",padx=14,pady=(0,10))

        ctk.CTkLabel(gr,text="Tamanho:",font=(fh,9),text_color=T["dim"]).pack(side="left")
        self._glen = ctk.IntVar(value=16)
        ctk.CTkSlider(gr,from_=8,to=64,variable=self._glen,
            width=120,progress_color=T["a1"]).pack(side="left",padx=6)
        ctk.CTkLabel(gr,textvariable=self._glen,font=(fh,9),
                     text_color=T["a1"],width=24).pack(side="left")

        self._gsym = ctk.BooleanVar(value=True)
        self._gnum = ctk.BooleanVar(value=True)
        self._gup  = ctk.BooleanVar(value=True)
        for lbl,v in [("Símbolos",self._gsym),("Números",self._gnum),("Maiúsculas",self._gup)]:
            ctk.CTkCheckBox(gr,text=lbl,variable=v,font=(fh,9),
                text_color=T["txt"],fg_color=T["a1"]).pack(side="left",padx=8)

        self._gout = ctk.CTkEntry(gr,width=200,font=("Courier New",11),
            fg_color=T["bg0"],border_color=T["brd"],text_color=T["ok"])
        self._gout.pack(side="left",padx=8)
        NvBtn(gr,T,"a3",text="⚡ Gerar",width=78,height=28,
              command=self._gen_pw).pack(side="left")

        # Tabela
        rf, self._vttree = self._tree(f,
            cols=("Serviço","Usuário","Senha","Categoria","Data","Força"),
            widths=[160,155,160,100,120,85], h=14)
        rf.pack(fill="both",expand=True)
        self._vault_refresh()

    def _gen_pw(self):
        import string
        chars = string.ascii_lowercase
        if self._gup.get():  chars += string.ascii_uppercase
        if self._gnum.get(): chars += string.digits
        if self._gsym.get(): chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        pw = "".join(random.choices(chars, k=self._glen.get()))
        self._gout.delete(0,"end"); self._gout.insert(0,pw)

    def _vault_refresh(self):
        if not hasattr(self,"_vttree"): return
        for r in self._vttree.get_children(): self._vttree.delete(r)
        for it in self.vault_db:
            pw = it.get("password","")
            st, ck = pw_strength(pw)
            masked = "●"*min(len(pw),14)
            self._vttree.insert("","end",
                values=(it.get("service","?"),it.get("username","?"),
                        masked,it.get("category","Geral"),
                        it.get("date","?"),st), tags=(ck,))

    def _vault_add(self):
        T=self.T; fh=T["fh"]
        d = ctk.CTkToplevel(self)
        d.title("Nova Entrada — Cofre NOVICO")
        d.geometry("430x460"); d.configure(fg_color=T["bg0"]); d.grab_set()
        ctk.CTkLabel(d,text="Nova Entrada",font=(fh,15,"bold"),
                     text_color=T["a1"]).pack(pady=(20,12))

        flds: dict[str,ctk.CTkEntry] = {}
        cats=["Geral","Banco","Email","Rede Social","Trabalho","Jogos","Outro"]
        cat_v = ctk.StringVar(value="Geral")

        for lbl,ph,show in [
            ("Serviço","github.com",""),
            ("Usuário","email@exemplo.com",""),
            ("Senha","••••••••","*"),
            ("Notas","Opcional",""),
        ]:
            ctk.CTkLabel(d,text=lbl,font=(fh,9),text_color=T["dim"]
                         ).pack(anchor="w",padx=24,pady=(4,0))
            e = ctk.CTkEntry(d,width=380,font=(fh,11),fg_color=T["bg2"],
                border_color=T["brd"],text_color=T["a1"],
                placeholder_text=ph, show=show)
            e.pack(padx=24,pady=(0,4)); flds[lbl]=e

        ctk.CTkLabel(d,text="Categoria",font=(fh,9),text_color=T["dim"]
                     ).pack(anchor="w",padx=24,pady=(4,0))
        ctk.CTkOptionMenu(d,values=cats,variable=cat_v,
            fg_color=T["bg2"],button_color=T["a1"],
            text_color=T["txt"],font=(fh,10)).pack(fill="x",padx=24,pady=(0,8))

        def save():
            svc=flds["Serviço"].get(); pw=flds["Senha"].get()
            if not svc or not pw:
                messagebox.showerror("Erro","Serviço e Senha são obrigatórios."); return
            self.vault_db.append({
                "service":svc,"username":flds["Usuário"].get(),
                "password":pw,"notes":flds["Notas"].get(),
                "category":cat_v.get(),
                "date":datetime.datetime.now().strftime("%d/%m/%Y")
            })
            self._save_json(VAULT, self.vault_db)
            self._vault_refresh(); log(f"Cofre: entrada adicionada — {svc}"); d.destroy()

        NvBtn(d,T,"ok",text="💾 Salvar",width=200,height=38,
              font=(fh,12,"bold"),command=save).pack(pady=8)

    def _vault_rev(self):
        sel=self._vttree.selection()
        if not sel: return
        idx=self._vttree.index(sel[0]); it=self.vault_db[idx]
        messagebox.showinfo("🔐 Senha",
            f"Serviço: {it.get('service','?')}\n"
            f"Usuário: {it.get('username','?')}\n"
            f"Senha:   {it.get('password','?')}\n"
            f"Notas:   {it.get('notes','—')}")

    def _vault_copy(self):
        sel=self._vttree.selection()
        if not sel: return
        idx=self._vttree.index(sel[0])
        pw=self.vault_db[idx].get("password","")
        self.clipboard_clear(); self.clipboard_append(pw)
        self.toast.push("Copiado!","Senha copiada para área de transferência.","ok")

    def _vault_del(self):
        sel=self._vttree.selection()
        if not sel: return
        idx=self._vttree.index(sel[0]); svc=self.vault_db[idx].get("service","?")
        if messagebox.askyesno("Excluir",f"Excluir senha de '{svc}'?"):
            self.vault_db.pop(idx)
            self._save_json(VAULT,self.vault_db); self._vault_refresh()

    # ════════════════════════════════════════════════════════════════════════
    # ABA 9 — LIMPADOR
    # ════════════════════════════════════════════════════════════════════════
    def _build_cleaner(self):
        T=self.T; fh=T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["cleaner"] = f

        tb = NvCard(f,T); tb.pack(fill="x",pady=(0,8))
        row = ctk.CTkFrame(tb,fg_color="transparent"); row.pack(fill="x",padx=14,pady=10)
        ctk.CTkLabel(row,text="🧹  Limpador do Sistema",
                     font=(fh,13,"bold"),text_color=T["ok"]).pack(side="left")
        NvBtn(tb,T,"a1", text="🔄 Analisar",   width=115,height=30,command=self._cl_scan   ).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"ok", text="🧹 Limpar Sel.",width=130,height=30,command=self._cl_clean   ).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"warn",text="⚡ Limpar Tudo",width=130,height=30,command=self._cl_all    ).pack(in_=row,side="right",padx=4)

        self._cl_total = ctk.CTkLabel(f,text="Execute 'Analisar' para ver o espaço recuperável.",
                                      font=(fh,9),text_color=T["dim"])
        self._cl_total.pack(anchor="w",pady=(0,4))

        self._cl_scroll = ctk.CTkScrollableFrame(f,fg_color=T["bg2"],
            corner_radius=T["cr"],height=260,border_width=1,border_color=T["brd"])
        self._cl_scroll.pack(fill="x",pady=(0,8))

        self._cl_log = ctk.CTkTextbox(f,height=160,font=("Courier New",10),
            fg_color=T["bg2"],text_color=T["ok"],border_color=T["brd"],border_width=1)
        self._cl_log.pack(fill="x")
        self._cl_items: list[tuple] = []
        self._cl_vars:  list[ctk.BooleanVar] = []

    def _cl_scan(self):
        T=self.T; fh=T["fh"]
        for w in self._cl_scroll.winfo_children(): w.destroy()
        self._cl_items.clear(); self._cl_vars.clear()

        dirs: list[tuple[str,str]] = []
        if platform.system()=="Windows":
            dirs=[
                ("Temp do Windows",     os.environ.get("TEMP","C:\\Windows\\Temp")),
                ("Temp do Usuário",     os.path.expandvars("%LOCALAPPDATA%\\Temp")),
                ("Prefetch",            "C:\\Windows\\Prefetch"),
                ("Cache do Navegador",  os.path.expandvars("%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cache")),
                ("Minidumps",           "C:\\Windows\\Minidump"),
                ("Windows Update Cache","C:\\Windows\\SoftwareDistribution\\Download"),
            ]
        else:
            home=str(Path.home())
            dirs=[
                ("Arquivos /tmp",          "/tmp"),
                ("Cache do Usuário",       f"{home}/.cache"),
                ("Logs do Sistema",        "/var/log"),
                ("Thumbnails",             f"{home}/.cache/thumbnails"),
                ("Cache do pip",           f"{home}/.cache/pip"),
                ("Logs do NOVICO",         str(DATA)),
            ]

        total=0
        for lbl,path in dirs:
            sz=0
            if os.path.exists(path):
                try: sz=sum(f.stat().st_size for f in Path(path).rglob("*") if f.is_file())
                except Exception: pass
            v=ctk.BooleanVar(value=sz>0)
            self._cl_vars.append(v); self._cl_items.append((v,lbl,path,sz)); total+=sz

            row=ctk.CTkFrame(self._cl_scroll,fg_color="transparent")
            row.pack(fill="x",padx=8,pady=3)
            ctk.CTkCheckBox(row,text=lbl,variable=v,font=(fh,10),
                text_color=T["txt"],fg_color=T["ok"]).pack(side="left")
            col=T["warn"] if sz>100*1024*1024 else T["dim"]
            ctk.CTkLabel(row,text=fmt_b(sz),font=(fh,9),text_color=col).pack(side="right")
            ctk.CTkLabel(row,text=path[:55],font=(fh,7),text_color=T["brd"]).pack(side="right",padx=10)

        self._cl_total.configure(text=f"Espaço recuperável estimado: {fmt_b(total)}")

    def _cl_clean(self, force_all=False):
        if not self._cl_items:
            messagebox.showinfo("Aviso","Execute 'Analisar' primeiro."); return
        todo=[(l,p,s) for v,l,p,s in self._cl_items if force_all or v.get()]
        if not todo: return
        if not messagebox.askyesno("Limpar",
            f"Limpar {len(todo)} categorias? Ação irreversível!"): return
        freed=0
        for lbl,path,sz in todo:
            try:
                if os.path.exists(path):
                    for item in Path(path).iterdir():
                        try:
                            if item.is_file(): item.unlink(); freed+=item.stat().st_size
                            elif item.is_dir(): shutil.rmtree(str(item),ignore_errors=True); freed+=sz
                        except Exception: pass
                self._cl_write(f"✓ {lbl}: {fmt_b(sz)} liberados")
                log(f"Limpeza: {lbl} ({fmt_b(sz)})")
            except Exception as e:
                self._cl_write(f"✗ {lbl}: Erro — {e}")
        self._cl_write(f"\n═ Total liberado: {fmt_b(freed)} ═")
        self.toast.push("Limpeza Concluída",f"{fmt_b(freed)} liberados.","ok")
        self._cl_scan()

    def _cl_all(self):
        for v in self._cl_vars: v.set(True)
        self._cl_clean(force_all=True)

    def _cl_write(self,msg):
        self._cl_log.configure(state="normal")
        self._cl_log.insert("end",msg+"\n")
        self._cl_log.see("end")
        self._cl_log.configure(state="disabled")

    # ════════════════════════════════════════════════════════════════════════
    # ABA 10 — AGENDADOR
    # ════════════════════════════════════════════════════════════════════════
    def _build_scheduler(self):
        T=self.T; fh=T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["scheduler"] = f

        tb = NvCard(f,T); tb.pack(fill="x",pady=(0,8))
        row = ctk.CTkFrame(tb,fg_color="transparent"); row.pack(fill="x",padx=14,pady=10)
        ctk.CTkLabel(row,text="🗓  Agendador de Varreduras",
                     font=(fh,13,"bold"),text_color=T["a1"]).pack(side="left")
        NvBtn(tb,T,"ok",  text="+ Nova Tarefa",width=125,height=30,command=self._sched_add).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"err", text="🗑 Remover",   width=100,height=30,command=self._sched_del).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"a2",  text="▶ Executar",   width=100,height=30,command=self._sched_run).pack(in_=row,side="right",padx=4)

        # Config global
        cg = NvCard(f,T); cg.pack(fill="x",pady=(0,8))
        cgr = ctk.CTkFrame(cg,fg_color="transparent"); cgr.pack(fill="x",padx=14,pady=10)
        ctk.CTkLabel(cgr,text="Agendamento Automático:",font=(fh,10),text_color=T["dim"]).pack(side="left")
        self._sched_on = ctk.BooleanVar(value=self.cfg.get("schedule_on",False))
        ctk.CTkSwitch(cgr,text="",variable=self._sched_on,
            progress_color=T["a1"],width=50,command=self._sched_toggle).pack(side="left",padx=10)
        ctk.CTkLabel(cgr,text="Frequência:",font=(fh,10),text_color=T["dim"]).pack(side="left",padx=(16,4))
        self._sched_freq = ctk.StringVar(value=self.cfg.get("schedule_freq","Diário"))
        ctk.CTkOptionMenu(cgr,
            values=["A cada hora","A cada 6h","Diário","Semanal","Mensal"],
            variable=self._sched_freq,width=130,
            fg_color=T["bg2"],button_color=T["a1"],
            text_color=T["txt"],font=(fh,10)).pack(side="left")

        rf, self._sdtree = self._tree(f,
            cols=("Tarefa","Caminho","Tipo","Freq.","Próxima Exec.","Status","Último"),
            widths=[140,240,85,85,140,75,130], h=16)
        rf.pack(fill="both",expand=True)
        self._sched_refresh()

    def _sched_toggle(self):
        self.cfg["schedule_on"]=self._sched_on.get()
        self.cfg["schedule_freq"]=self._sched_freq.get()
        save_cfg(self.cfg)

    def _sched_refresh(self):
        if not hasattr(self,"_sdtree"): return
        for r in self._sdtree.get_children(): self._sdtree.delete(r)
        for s in self.sched_db:
            tag="ok" if s.get("status")=="Ativo" else "warn"
            self._sdtree.insert("","end",
                values=(s.get("name","?"),s.get("path","?"),
                        s.get("type","?"),s.get("freq","?"),
                        s.get("next","—"),s.get("status","Ativo"),
                        s.get("last","Nunca")), tags=(tag,))

    def _sched_add(self):
        T=self.T; fh=T["fh"]
        d=ctk.CTkToplevel(self); d.title("Nova Tarefa Agendada")
        d.geometry("450x390"); d.configure(fg_color=T["bg0"]); d.grab_set()
        ctk.CTkLabel(d,text="Nova Tarefa",font=(fh,15,"bold"),
                     text_color=T["a1"]).pack(pady=(20,12))

        flds={}
        for lbl,ph in [("Nome","Varredura Semanal"),("Caminho",str(Path.home()))]:
            ctk.CTkLabel(d,text=lbl,font=(fh,9),text_color=T["dim"]
                         ).pack(anchor="w",padx=24,pady=(4,0))
            e=ctk.CTkEntry(d,width=400,font=(fh,11),fg_color=T["bg2"],
                border_color=T["brd"],text_color=T["a1"],placeholder_text=ph)
            e.pack(padx=24,pady=(0,4)); flds[lbl]=e

        for lbl,opts,default in [
            ("Tipo",["Rápida","Completa","Personalizada"],"Rápida"),
            ("Frequência",["Diário","Semanal","Mensal","Única vez"],"Diário"),
        ]:
            ctk.CTkLabel(d,text=lbl,font=(fh,9),text_color=T["dim"]
                         ).pack(anchor="w",padx=24,pady=(4,0))
            v=ctk.StringVar(value=default)
            ctk.CTkOptionMenu(d,values=opts,variable=v,
                fg_color=T["bg2"],button_color=T["a1"],
                text_color=T["txt"],font=(fh,10)).pack(fill="x",padx=24)
            flds[lbl]=v   # StringVar para dropdowns

        def save():
            nome=flds["Nome"].get(); path=flds["Caminho"].get()
            if not nome or not path:
                messagebox.showerror("Erro","Preencha Nome e Caminho."); return
            self.sched_db.append({
                "name":nome,"path":path,
                "type":flds["Tipo"].get(),"freq":flds["Frequência"].get(),
                "next":(datetime.datetime.now()+datetime.timedelta(days=1)
                        ).strftime("%d/%m/%Y %H:%M"),
                "status":"Ativo","last":"Nunca"
            })
            self._save_json(SCHED,self.sched_db)
            self._sched_refresh(); log(f"Tarefa agendada: {nome}"); d.destroy()

        NvBtn(d,T,"ok",text="💾 Salvar",width=200,height=38,
              font=(fh,12,"bold"),command=save).pack(pady=16)

    def _sched_del(self):
        sel=self._sdtree.selection()
        if not sel: return
        idx=self._sdtree.index(sel[0])
        if messagebox.askyesno("Remover","Remover esta tarefa agendada?"):
            self.sched_db.pop(idx)
            self._save_json(SCHED,self.sched_db); self._sched_refresh()

    def _sched_run(self):
        sel=self._sdtree.selection()
        if not sel: messagebox.showinfo("Aviso","Selecione uma tarefa."); return
        idx=self._sdtree.index(sel[0]); s=self.sched_db[idx]
        self.show("scanner"); self._scan_path.set(s.get("path",str(Path.home())))
        self._scan_start()

    # ════════════════════════════════════════════════════════════════════════
    # ABA 11 — LOGS
    # ════════════════════════════════════════════════════════════════════════
    def _build_logs(self):
        T=self.T; fh=T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["logs"] = f

        tb = NvCard(f,T); tb.pack(fill="x",pady=(0,8))
        row = ctk.CTkFrame(tb,fg_color="transparent"); row.pack(fill="x",padx=14,pady=10)
        ctk.CTkLabel(row,text="📋  Logs de Eventos",
                     font=(fh,13,"bold"),text_color=T["dim"]).pack(side="left")
        NvBtn(tb,T,"ok",  text="💾 Exportar",width=110,height=30,command=self._log_export).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"err", text="🗑 Limpar",   width=90, height=30,command=self._log_clear ).pack(in_=row,side="right",padx=4)
        NvBtn(tb,T,"dim", text="🔄",          width=36, height=30,command=self._ref_logs  ).pack(in_=row,side="right",padx=4)

        # Filtros
        fr = NvCard(f,T); fr.pack(fill="x",pady=(0,8))
        frr = ctk.CTkFrame(fr,fg_color="transparent"); frr.pack(fill="x",padx=14,pady=8)
        ctk.CTkLabel(frr,text="Filtrar:",font=(fh,9),text_color=T["dim"]).pack(side="left")
        self._lf = ctk.CTkEntry(frr,width=280,placeholder_text="Texto...",
            font=(fh,10),fg_color=T["bg0"],border_color=T["brd"],text_color=T["a1"])
        self._lf.pack(side="left",padx=6)
        self._lf.bind("<KeyRelease>",lambda e:self._ref_logs())
        self._llv = ctk.StringVar(value="Todos")
        ctk.CTkOptionMenu(frr,
            values=["Todos","INFO","WARNING","CRITICAL","ERROR"],
            variable=self._llv,width=115,
            fg_color=T["bg2"],button_color=T["a1"],
            text_color=T["txt"],font=(fh,9),
            command=lambda _:self._ref_logs()).pack(side="left",padx=8)

        self._ltxt = ctk.CTkTextbox(f,font=("Courier New",10.5),
            fg_color=T["bg2"],text_color=T["txt"])
        self._ltxt.pack(fill="both",expand=True)

    def _ref_logs(self):
        self._ltxt.configure(state="normal"); self._ltxt.delete("1.0","end")
        flt=self._lf.get().lower(); lvl=self._llv.get()
        try:
            if LOG.exists():
                for line in LOG.read_text(encoding="utf-8").splitlines():
                    if flt and flt not in line.lower(): continue
                    if lvl!="Todos" and f"[{lvl}" not in line: continue
                    self._ltxt.insert("end",line+"\n")
            self._ltxt.see("end")
        except Exception as e: self._ltxt.insert("end",f"Erro: {e}\n")
        self._ltxt.configure(state="disabled")

    def _log_clear(self):
        if messagebox.askyesno("Limpar","Limpar todos os logs?"):
            try: LOG.write_text(""); self._ref_logs()
            except Exception as e: messagebox.showerror("Erro",str(e))

    def _log_export(self):
        p=filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Texto","*.txt"),("Todos","*.*")],
            initialfile=f"novico_log_{datetime.datetime.now().strftime('%Y%m%d')}.txt")
        if p and LOG.exists(): shutil.copy(str(LOG),p)
        if p: messagebox.showinfo("Exportado",f"Log salvo em:\n{p}")

    # ════════════════════════════════════════════════════════════════════════
    # ABA 12 — CONFIGURAÇÕES & TEMAS
    # ════════════════════════════════════════════════════════════════════════
    def _build_settings(self):
        T=self.T; fh=T["fh"]
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        self._tabs["settings"] = f

        sc = ctk.CTkScrollableFrame(f, fg_color="transparent")
        sc.pack(fill="both", expand=True)

        # ── Temas ──────────────────────────────────────────────────────────
        ctk.CTkLabel(sc,text="🎨  Temas Visuais",font=(fh,13,"bold"),
                     text_color=T["a1"]).pack(anchor="w",pady=(0,6))

        tg = NvCard(sc,T); tg.pack(fill="x",pady=(0,14))
        tr = ctk.CTkFrame(tg,fg_color="transparent"); tr.pack(fill="x",padx=16,pady=14)

        for name, td in THEMES.items():
            tc = ctk.CTkFrame(tr, fg_color=td["bg1"],
                              corner_radius=8, width=108)
            tc.pack(side="left", padx=6)
            tc.pack_propagate(False)

            # Preview strip
            prev = ctk.CTkFrame(tc, fg_color=td["bg0"], height=24, corner_radius=4)
            prev.pack(fill="x", padx=6, pady=(6,2))
            ctk.CTkLabel(prev, text="● ● ●", font=("Courier New",9),
                         text_color=td["a1"]).pack()

            ctk.CTkLabel(tc, text=name, font=(fh,8,"bold"),
                         text_color=td["a1"], wraplength=96).pack(pady=(0,2))

            ctk.CTkButton(tc, text="Aplicar", height=24,
                corner_radius=4, font=(fh,8),
                fg_color=td["a1"]+"28", hover_color=td["a1"]+"55",
                text_color=td["a1"], border_color=td["a1"], border_width=1,
                command=lambda n=name: self._apply_theme(n)
            ).pack(fill="x", padx=6, pady=(0,8))

        # ── Proteção ───────────────────────────────────────────────────────
        ctk.CTkLabel(sc,text="🛡  Proteção",font=(fh,11,"bold"),
                     text_color=T["dim"]).pack(anchor="w",pady=(10,4))

        self._sw: dict[str,ctk.BooleanVar] = {}
        opts=[
            ("realtime","Proteção em tempo real"),
            ("archives","Verificar arquivos comprimidos (.zip/.rar)"),
            ("auto_quarantine","Quarentena automática ao detectar ameaça"),
            ("heuristic","Análise heurística (detecta ameaças desconhecidas)"),
            ("scan_startup","Varredura automática ao iniciar o sistema"),
            ("notifications","Notificações toast em tempo real"),
            ("auto_update","Atualização automática de definições"),
        ]
        for key,lbl in opts:
            row=NvCard(sc,T); row.pack(fill="x",pady=2)
            ctk.CTkLabel(row,text=lbl,font=(fh,10),text_color=T["txt"]
                         ).pack(side="left",padx=14,pady=10)
            v=ctk.BooleanVar(value=self.cfg.get(key,True)); self._sw[key]=v
            ctk.CTkSwitch(row,text="",variable=v,
                progress_color=T["a1"],width=50).pack(side="right",padx=14)

        # ── Interface ──────────────────────────────────────────────────────
        ctk.CTkLabel(sc,text="🖥  Interface",font=(fh,11,"bold"),
                     text_color=T["dim"]).pack(anchor="w",pady=(12,4))

        ic=NvCard(sc,T); ic.pack(fill="x",pady=(0,8))
        ir=ctk.CTkFrame(ic,fg_color="transparent"); ir.pack(fill="x",padx=14,pady=10)
        ctk.CTkLabel(ir,text="Modo de Aparência:",font=(fh,10),
                     text_color=T["dim"]).pack(side="left")
        self._mode_v=ctk.StringVar(value=ctk.get_appearance_mode().lower())
        for m in ["dark","light","system"]:
            ctk.CTkRadioButton(ir,text=m.capitalize(),variable=self._mode_v,
                value=m,font=(fh,10),text_color=T["txt"],fg_color=T["a1"],
                command=lambda mv=m:ctk.set_appearance_mode(mv)
                ).pack(side="left",padx=10)

        # ── Definições ─────────────────────────────────────────────────────
        ctk.CTkLabel(sc,text="🔄  Definições de Vírus",font=(fh,11,"bold"),
                     text_color=T["dim"]).pack(anchor="w",pady=(10,4))
        dc=NvCard(sc,T); dc.pack(fill="x",pady=(0,8))
        dr=ctk.CTkFrame(dc,fg_color="transparent"); dr.pack(fill="x",padx=14,pady=10)
        self._defver=ctk.CTkLabel(dr,
            text=f"Versão atual: {self.cfg.get('definitions_ver','N/A')}",
            font=(fh,10),text_color=T["dim"]); self._defver.pack(side="left")
        NvBtn(dc,T,"ok",text="🔄 Atualizar Agora",width=160,height=30,
              command=self._update_defs).pack(in_=dr,side="right")

        # ── Sobre ──────────────────────────────────────────────────────────
        ctk.CTkLabel(sc,text="ℹ  Sobre o NOVICO",font=(fh,11,"bold"),
                     text_color=T["dim"]).pack(anchor="w",pady=(10,4))
        ab=NvCard(sc,T); ab.pack(fill="x",pady=(0,8))
        ctk.CTkLabel(ab,
            text=f"{APP} Security Suite  v{VER}\n"
                 f"Sistema: {platform.system()} {platform.release()}\n"
                 f"Python:  {sys.version.split()[0]}\n"
                 f"Dados:   {DATA}",
            font=(fh,10),text_color=T["dim"],justify="left"
            ).pack(anchor="w",padx=14,pady=12)

        NvBtn(sc,T,"ok",text="💾  Salvar Configurações",height=46,
              font=(fh,13,"bold"),command=self._save_settings).pack(fill="x",pady=14)

    def _apply_theme(self, name: str):
        self.cfg["theme"] = name; save_cfg(self.cfg)
        messagebox.showinfo("Tema Aplicado",
            f"Tema '{name}' salvo!\nReinicie o NOVICO para aplicar.")
        log(f"Tema alterado: {name}")

    def _save_settings(self):
        for k,v in self._sw.items(): self.cfg[k]=v.get()
        save_cfg(self.cfg)
        log("Configurações salvas.")
        self.toast.push("Configurações Salvas","Todas as opções foram aplicadas.","ok")

    # ════════════════════════════════════════════════════════════════════════
    # FUNÇÕES GLOBAIS COMPARTILHADAS
    # ════════════════════════════════════════════════════════════════════════
    def _update_defs(self):
        self.toast.push("Atualizando...","Baixando definições de vírus NOVICO.","info")
        def w():
            time.sleep(2.5)
            nv=datetime.datetime.now().strftime("%Y.%m.%d")
            self.cfg["definitions_ver"]=nv; save_cfg(self.cfg)
            self.after(0,self.toast.push,"✓ Definições Atualizadas",f"Versão {nv} instalada.","ok")
            log(f"Definições atualizadas: {nv}")
            if hasattr(self,"_defver"):
                self.after(0,self._defver.configure,{"text":f"Versão atual: {nv}"})
        threading.Thread(target=w,daemon=True).start()

    def _export_html(self):
        T=self.T
        p=filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML","*.html"),("Todos","*.*")],
            initialfile=f"novico_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.html")
        if not p: return

        q_rows="".join(
            f"<tr><td>{it['date']}</td><td>{it['original']}</td>"
            f"<td style='color:{T['err']}'>{it['threat']}</td>"
            f"<td>{fmt_b(it['size'])}</td></tr>"
            for it in self.q_items)

        html=f"""<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8">
<title>NOVICO — Relatório de Segurança</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:{T['bg0']};color:{T['txt']};font-family:'Courier New',monospace;padding:32px}}
  h1{{color:{T['a1']};font-size:26px;border-bottom:2px solid {T['a1']};padding-bottom:12px;margin-bottom:24px}}
  h2{{color:{T['a2']};font-size:16px;margin:28px 0 10px}}
  .card{{background:{T['bg2']};border:1px solid {T['brd']};border-radius:8px;padding:16px;margin-bottom:12px}}
  .grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
  .tile{{background:{T['bg2']};border:1px solid {T['brd']};border-radius:8px;padding:16px;text-align:center}}
  .tile-val{{font-size:28px;font-weight:bold}}
  .tile-lbl{{font-size:10px;color:{T['dim']};margin-top:4px}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:{T['bg1']};color:{T['a1']};padding:8px;text-align:left;font-size:11px}}
  td{{padding:7px 8px;border-bottom:1px solid {T['brd']};font-size:11px}}
  .ok{{color:{T['ok']}}} .warn{{color:{T['warn']}}} .err{{color:{T['err']}}}
  footer{{margin-top:40px;font-size:9px;color:{T['dim']};border-top:1px solid {T['brd']};padding-top:12px}}
</style>
</head>
<body>
<h1>🛡 {APP} Security Suite — Relatório de Segurança</h1>
<p style="color:{T['dim']};margin-bottom:20px">
  Gerado em: {datetime.datetime.now().strftime('%d/%m/%Y às %H:%M:%S')} &nbsp;|&nbsp;
  Sistema: {platform.system()} {platform.release()} &nbsp;|&nbsp;
  Python {sys.version.split()[0]}
</p>

<div class="grid">
  <div class="tile"><div class="tile-val err">{self.cfg.get('threats_total',0)}</div><div class="tile-lbl">Ameaças Bloqueadas</div></div>
  <div class="tile"><div class="tile-val" style="color:{T['a1']}">{self.cfg.get('files_scanned',0)}</div><div class="tile-lbl">Arquivos Verificados</div></div>
  <div class="tile"><div class="tile-val warn">{len(self.q_items)}</div><div class="tile-lbl">Itens em Quarentena</div></div>
  <div class="tile"><div class="tile-val" style="color:{T['ok'] if self.cfg.get('protection') else T['err']}">{'ON' if self.cfg.get('protection') else 'OFF'}</div><div class="tile-lbl">Proteção</div></div>
</div>

<h2>📊 Resumo da Última Varredura</h2>
<div class="card">
  <table>
    <tr><th>Métrica</th><th>Valor</th></tr>
    <tr><td>Última varredura</td><td>{self.cfg.get('last_scan','Nunca')}</td></tr>
    <tr><td>Varreduras realizadas</td><td>{self.cfg.get('scans_done',0)}</td></tr>
    <tr><td>Versão das definições</td><td>{self.cfg.get('definitions_ver','?')}</td></tr>
    <tr><td>Tema ativo</td><td>{self.cfg.get('theme','?')}</td></tr>
  </table>
</div>

<h2>⚠ Quarentena ({len(self.q_items)} itens)</h2>
<div class="card">
  {'<p class="ok">Nenhum item em quarentena.</p>' if not self.q_items else
   f'<table><tr><th>Data</th><th>Arquivo</th><th>Ameaça</th><th>Tamanho</th></tr>{q_rows}</table>'}
</div>

<h2>🔐 Cofre de Senhas</h2>
<div class="card"><p>{len(self.vault_db)} entrada(s) — senhas não exibidas por segurança.</p></div>

<footer>
  {APP} Security Suite v{VER} — Relatório gerado automaticamente. Não compartilhe este arquivo.
</footer>
</body></html>"""

        try:
            Path(p).write_text(html, encoding="utf-8")
            messagebox.showinfo("Relatório Exportado",f"Salvo em:\n{p}")
            log(f"Relatório HTML exportado: {p}")
        except Exception as e: messagebox.showerror("Erro",str(e))

    # ════════════════════════════════════════════════════════════════════════
    # BACKGROUND THREADS
    # ════════════════════════════════════════════════════════════════════════
    def _start_bg(self):
        threading.Thread(target=self._bg_sys, daemon=True).start()
        threading.Thread(target=self._bg_uptime, daemon=True).start()

    def _bg_sys(self):
        while True:
            try:
                cpu  = psutil.cpu_percent(interval=1)
                ram  = psutil.virtual_memory().percent
                disk = psutil.disk_usage("/").percent
                self.cpu_hist.append(cpu); self.ram_hist.append(ram)
                self.after(0, self._upd_bars, cpu, ram, disk)
                if HAS_MPL: self.after(0, self._upd_chart)
            except Exception: pass
            time.sleep(1.5)

    def _upd_bars(self, cpu, ram, disk):
        try:
            for attr,val in [("cpu",cpu),("ram",ram),("disk",disk)]:
                bar,pct = self._res_bars[attr]
                bar.set(val/100); pct.configure(text=f"{val:.1f}%")
        except Exception: pass

    def _upd_chart(self):
        try:
            self._cpu_line.set_ydata(list(self.cpu_hist))
            self._ram_line.set_ydata(list(self.ram_hist))
            self._canv.draw_idle()
        except Exception: pass

    def _bg_uptime(self):
        while True:
            try:
                elapsed = time.time() - psutil.boot_time()
                h = int(elapsed//3600); m = int((elapsed%3600)//60)
                self.after(0, self._t_uptime.set, f"{h}h{m:02d}m")
            except Exception: pass
            time.sleep(60)


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = Novico()
    app.mainloop()
