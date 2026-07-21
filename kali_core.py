#!/usr/bin/env python3
"""
kali_core — KaliSuite araçlarının ortak çekirdeği.

Bu modül; karanlık tema, komut çalıştırıcı (subprocess + thread), canlı log,
sonuç kaydetme ve güvenlik doğrulaması gibi HER araçta aynı olan altyapıyı sağlar.
Her araç (KaliRecon, ileride KaliBrute...) bu çekirdeği kullanır ve yalnızca kendi
profil listesini + ayarlarını (ToolConfig) verir.

Kullanım:
    from kali_core import ToolConfig, KaliToolApp
    KaliToolApp(ToolConfig(...)).mainloop()

YASAL UYARI: Bu araçlar yalnızca SAHİBİ OLDUĞUNUZ veya YAZILI İZNE sahip olduğunuz
sistemlerde kullanılmalıdır. İzinsiz tarama/erişim pek çok ülkede suçtur.
"""

import difflib
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from tkinter import filedialog

import customtkinter as ctk

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# --- Hacker teması: koyu siyah + terminal yeşili ------------------------------
COL_BG = "#0a0a0a"          # ana pencere arka planı (neredeyse siyah)
COL_PANEL = "#0d0f0d"       # kenar çubuğu / paneller (yeşilimsi siyah)
COL_CONSOLE = "#000000"     # log ekranı (saf siyah terminal)
COL_ENTRY = "#121512"       # giriş alanları
COL_HINT_BG = "#0b160b"     # ipucu kutusu arka planı (koyu yeşil)
COL_TEXT = "#3fd66b"        # terminal yeşili metin
COL_GREEN = "#5df58a"       # başlık / vurgu yeşili
COL_ACCENT = "#166534"      # buton yeşili
COL_ACCENT_HOVER = "#1f8a48"  # buton hover yeşili


def is_root() -> bool:
    """Linux'ta root muyuz? (Windows'ta geteuid yoktur -> False)."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def find_existing(paths: list[str]) -> str:
    """Verilen yollardan var olan ilkini döndürür (wordlist otomatik seçimi)."""
    for p in paths:
        if os.path.isfile(p):
            return p
    return ""


@dataclass
class ToolConfig:
    """Bir aracın çekirdeğe verdiği ayarlar. Sadece araca özgü kısımlar burada."""
    app_name: str                       # örn. "KaliRecon"
    subtitle: str                       # kenar çubuğu alt başlığı
    profiles: dict                      # profil sözlüğü (tool/args/hint/...)
    tools: list[str]                    # araç seçici etiketleri (örn. ["Nmap", ...])
    allowed_tools: set[str]             # çalıştırılmasına izin verilen ikili adları
    results_dir: Path                   # otomatik kayıt klasörü
    default_wordlists: list[str] = field(default_factory=list)
    window_title: str = ""              # boşsa app_name kullanılır
    target_label: str = "Hedef IP / URL"
    target_placeholder: str = "192.168.1.10  |  http://hedef.local"
    wordlist_label: str = "Wordlist"
    start_label: str = "Başlat"
    ready_msg: str = "Hazır."
    root_warning: str = "Bu profil root yetkisi ister; root değilseniz eksik sonuç alabilirsiniz."
    # Tarama bitince çıktıya bakıp ek ipucu üreten opsiyonel geri çağrım.
    # imza: (cmd_listesi, kucuk_harf_tam_cikti) -> ipucu_metni | None
    output_hint: Optional[Callable[[list, str], Optional[str]]] = None


class KaliToolApp(ctk.CTk):
    """Tüm KaliSuite araçlarının ortak pencere/çalıştırıcı sınıfı."""

    def __init__(self, config: ToolConfig):
        super().__init__()
        self.cfg = config
        self.title(config.window_title or config.app_name)
        self.geometry("960x660")
        self.minsize(820, 560)
        self.configure(fg_color=COL_BG)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._proc: Optional[subprocess.Popen] = None
        self._worker: Optional[threading.Thread] = None
        self._scan_start: float = 0.0
        self._last_meta: tuple[str, str] = ("", "")
        self._has_results = False

        self._build_sidebar()
        self._build_main_area()
        self._on_profile_change(self.profile_menu.get())

        self.log(config.ready_msg, "info")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ UI --
    def _build_sidebar(self):
        bar = ctk.CTkFrame(self, width=300, corner_radius=0, fg_color=COL_PANEL)
        bar.grid(row=0, column=0, sticky="nsew")
        bar.grid_rowconfigure(12, weight=1)
        r = 0

        ctk.CTkLabel(bar, text=self.cfg.app_name, text_color=COL_GREEN,
                     font=ctk.CTkFont(size=22, weight="bold")
                     ).grid(row=r, column=0, padx=20, pady=(22, 2), sticky="w"); r += 1
        ctk.CTkLabel(bar, text=self.cfg.subtitle,
                     font=ctk.CTkFont(size=12), text_color="gray50"
                     ).grid(row=r, column=0, padx=20, pady=(0, 18), sticky="w"); r += 1

        # Araç seçici: seçim profil listesini o araca göre filtreler.
        ctk.CTkLabel(bar, text="Araç").grid(
            row=r, column=0, padx=20, pady=(0, 4), sticky="w"); r += 1
        self.tool_selector = ctk.CTkSegmentedButton(
            bar, values=self.cfg.tools, command=self._on_tool_change,
            selected_color=COL_ACCENT, selected_hover_color=COL_ACCENT_HOVER)
        self.tool_selector.set(self.cfg.tools[0])
        self.tool_selector.grid(row=r, column=0, padx=20, pady=(0, 14), sticky="ew"); r += 1

        # Hedef
        ctk.CTkLabel(bar, text=self.cfg.target_label).grid(
            row=r, column=0, padx=20, pady=(0, 4), sticky="w"); r += 1
        self.target_entry = ctk.CTkEntry(
            bar, placeholder_text=self.cfg.target_placeholder, fg_color=COL_ENTRY)
        self.target_entry.grid(row=r, column=0, padx=20, pady=(0, 14), sticky="ew"); r += 1
        self.target_entry.bind("<KeyRelease>", self._update_command_preview)

        # Profil (araç seçimine göre doldurulur)
        ctk.CTkLabel(bar, text="Profil").grid(
            row=r, column=0, padx=20, pady=(0, 4), sticky="w"); r += 1
        self.profile_menu = ctk.CTkOptionMenu(
            bar, values=self._profiles_for(self.cfg.tools[0]),
            command=self._on_profile_change, dynamic_resizing=False, width=260)
        self.profile_menu.grid(row=r, column=0, padx=20, pady=(0, 14), sticky="ew"); r += 1

        # Wordlist + Gözat butonu (yalnız gerekli profillerde etkin)
        ctk.CTkLabel(bar, text=self.cfg.wordlist_label).grid(
            row=r, column=0, padx=20, pady=(0, 4), sticky="w"); r += 1
        wl_row = ctk.CTkFrame(bar, fg_color="transparent")
        wl_row.grid(row=r, column=0, padx=20, pady=(0, 14), sticky="ew"); r += 1
        wl_row.grid_columnconfigure(0, weight=1)
        self.wordlist_entry = ctk.CTkEntry(
            wl_row, placeholder_text="/usr/share/wordlists/dirb/common.txt",
            fg_color=COL_ENTRY)
        self.wordlist_entry.grid(row=0, column=0, sticky="ew")
        self.wordlist_entry.bind("<KeyRelease>", self._update_command_preview)
        self.browse_btn = ctk.CTkButton(wl_row, text="Gözat", width=64,
                                        fg_color="gray30", hover_color="gray40",
                                        command=self.browse_wordlist)
        self.browse_btn.grid(row=0, column=1, padx=(6, 0))
        default_wl = find_existing(self.cfg.default_wordlists)
        if default_wl:
            self.wordlist_entry.insert(0, default_wl)

        # Akıllı ipucu / uyarı kutusu
        self.hint_box = ctk.CTkLabel(
            bar, text="", wraplength=250, justify="left",
            font=ctk.CTkFont(size=12), text_color=COL_GREEN,
            fg_color=COL_HINT_BG, corner_radius=8, anchor="w")
        self.hint_box.grid(row=r, column=0, padx=20, pady=(0, 16),
                           ipadx=10, ipady=10, sticky="ew"); r += 1

        # Butonlar
        self.start_btn = ctk.CTkButton(bar, text=self.cfg.start_label,
                                       fg_color=COL_ACCENT, hover_color=COL_ACCENT_HOVER,
                                       command=self.on_start)
        self.start_btn.grid(row=r, column=0, padx=20, pady=(0, 8), sticky="ew"); r += 1

        row = ctk.CTkFrame(bar, fg_color="transparent")
        row.grid(row=r, column=0, padx=20, pady=(0, 10), sticky="new")
        row.grid_columnconfigure((0, 1), weight=1)
        self.stop_btn = ctk.CTkButton(row, text="Durdur", state="disabled",
                                      fg_color="#7a2323", hover_color="#9a3030",
                                      command=self.on_stop)
        self.stop_btn.grid(row=0, column=0, padx=(0, 5), sticky="ew")
        self.clear_btn = ctk.CTkButton(row, text="Temizle", fg_color="gray30",
                                       hover_color="gray40", command=self.clear_log)
        self.clear_btn.grid(row=0, column=1, padx=(5, 0), sticky="ew")

    def _profiles_for(self, tool: str) -> list[str]:
        """Verilen araca ait profil adlarını döndürür."""
        t = tool.lower()
        return [name for name, p in self.cfg.profiles.items() if p["tool"] == t]

    def _on_tool_change(self, tool: str):
        """Araç seçimi değişince profil listesini o araca göre filtreler."""
        names = self._profiles_for(tool)
        self.profile_menu.configure(values=names)
        self.profile_menu.set(names[0])
        self._on_profile_change(names[0])

    def browse_wordlist(self):
        """Kullanıcının kendi wordlist dosyasını seçmesi için pencere açar."""
        start_dir = "/usr/share/wordlists"
        if not os.path.isdir(start_dir):
            start_dir = os.path.expanduser("~")
        path = filedialog.askopenfilename(
            title="Wordlist Seç", initialdir=start_dir,
            filetypes=[("Metin/Liste", "*.txt *.lst *.list"), ("Tüm dosyalar", "*.*")])
        if path:
            self.wordlist_entry.delete(0, "end")
            self.wordlist_entry.insert(0, path)
            self._update_command_preview()

    def _build_main_area(self):
        main = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        main.grid_rowconfigure(2, weight=1)
        main.grid_columnconfigure(0, weight=1)

        # Düzenlenebilir komut satırı: profil seçilince otomatik dolar,
        # çalıştırmadan önce elle değiştirilebilir.
        ctk.CTkLabel(main, text="Komut (çalıştırmadan önce düzenleyebilirsiniz)",
                     anchor="w", text_color="gray60",
                     font=ctk.CTkFont(size=12)).grid(row=0, column=0, sticky="ew")
        self.cmd_entry = ctk.CTkEntry(
            main, font=ctk.CTkFont(family="monospace", size=13),
            fg_color=COL_CONSOLE, text_color=COL_TEXT)
        self.cmd_entry.grid(row=1, column=0, sticky="ew", pady=(4, 10))

        self.log_box = ctk.CTkTextbox(
            main, font=ctk.CTkFont(family="monospace", size=13), wrap="none",
            fg_color=COL_CONSOLE, text_color=COL_TEXT)
        self.log_box.grid(row=2, column=0, sticky="nsew")
        self.log_box.configure(state="disabled")

        # Alt bar: durum + otomatik kaydet + sonuçlar + manuel kaydet
        bottom = ctk.CTkFrame(main, fg_color="transparent")
        bottom.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        bottom.grid_columnconfigure(0, weight=1)

        self.status = ctk.CTkLabel(bottom, text="Durum: Bekleniyor",
                                   anchor="w", text_color="gray70")
        self.status.grid(row=0, column=0, sticky="ew")

        self.autosave_var = ctk.BooleanVar(value=False)
        self.autosave_chk = ctk.CTkCheckBox(
            bottom, text="Otomatik kaydet", variable=self.autosave_var)
        self.autosave_chk.grid(row=0, column=1, padx=(10, 10))

        self.results_btn = ctk.CTkButton(bottom, text="Sonuçlar", width=100,
                                         fg_color="gray30", hover_color="gray40",
                                         command=self.open_results)
        self.results_btn.grid(row=0, column=2, padx=(0, 8))

        self.save_btn = ctk.CTkButton(bottom, text="Kaydet", width=110,
                                      fg_color=COL_ACCENT, hover_color=COL_ACCENT_HOVER,
                                      command=self.save_output)
        self.save_btn.grid(row=0, column=3)

    # --------------------------------------------------------- Etkileşim --
    def _on_profile_change(self, name: str):
        profile = self.cfg.profiles[name]
        self.hint_box.configure(text="> " + profile["hint"])
        state = "normal" if profile["needs_wordlist"] else "disabled"
        self.wordlist_entry.configure(state=state)
        self.browse_btn.configure(state=state)
        self._update_command_preview()

    def _update_command_preview(self, *_):
        """Profil/hedef/wordlist değiştikçe komut satırını günceller.
        Tarama sürerken dokunmaz (komut kilitli kalsın)."""
        if self._worker and self._worker.is_alive():
            return
        profile = self.cfg.profiles[self.profile_menu.get()]
        target = self.target_entry.get().strip() or "{target}"
        wordlist = self.wordlist_entry.get().strip() or "{wordlist}"
        self._set_command(self._build_command(profile, target, wordlist))

    def _set_command(self, cmd: list):
        """Komut satırını verilen argüman listesiyle (güvenli tırnaklı) doldurur."""
        self.cmd_entry.delete(0, "end")
        self.cmd_entry.insert(0, " ".join(shlex.quote(c) for c in cmd))

    def log(self, message: str, tag: str = ""):
        stamp = datetime.now().strftime("%H:%M:%S")
        prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]"}.get(tag, "")
        self.log_box.configure(state="normal")
        line = f"{stamp} {prefix} {message}" if prefix else message
        self.log_box.insert("end", line + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
        self._has_results = False

    # --------------------------------------------------------- Komut kurma --
    @staticmethod
    def _build_command(profile: dict, target: str, wordlist: str) -> list:
        cmd = [profile["tool"]]
        for arg in profile["args"]:
            cmd.append(arg.replace("{target}", target).replace("{wordlist}", wordlist))
        return cmd

    # --------------------------------------------------------- Başlat/Dur --
    def on_start(self):
        if self._worker and self._worker.is_alive():
            return

        name = self.profile_menu.get()
        profile = self.cfg.profiles[name]
        target = self.target_entry.get().strip()

        # Komutu düzenlenebilir alandan al (kullanıcı elle değiştirmiş olabilir).
        raw = self.cmd_entry.get().strip()
        if not raw:
            self.log("Komut alanı boş. Bir profil seçin veya komut girin.", "err")
            return
        try:
            cmd = shlex.split(raw)
        except ValueError as e:
            self.log(f"Komut ayrıştırılamadı (tırnak hatası?): {e}", "err")
            return
        if not cmd:
            self.log("Komut alanı boş.", "err")
            return

        # Güvenlik + akıllı düzeltme: izin verilmeyen/yanlış yazılmış araç.
        if cmd[0] not in self.cfg.allowed_tools:
            match = difflib.get_close_matches(
                cmd[0].lower(), self.cfg.allowed_tools, n=1, cutoff=0.5)
            if match:
                self._set_command([match[0]] + cmd[1:])
                self.log(f"'{cmd[0]}' geçersiz. '{match[0]}' olarak düzeltildi. "
                         f"Komutu kontrol edip tekrar '{self.cfg.start_label}'a basın.",
                         "warn")
            else:
                self.log(f"'{cmd[0]}' çalıştırılamaz. Yalnızca şu araçlar kullanılabilir: "
                         f"{', '.join(sorted(self.cfg.allowed_tools))}.", "err")
            return

        # Doldurulmamış yer tutucu kaldı mı? (hedef/wordlist girilmemiş)
        leftover = [c for c in cmd if "{target}" in c or "{wordlist}" in c]
        if leftover:
            if any("{target}" in c for c in leftover):
                self.log(f"Hedef alanı boş. Soldaki '{self.cfg.target_label}' kutusunu "
                         f"doldurun.", "err")
            if any("{wordlist}" in c for c in leftover):
                self.log("Wordlist seçilmedi. 'Gözat' ile bir kelime listesi seçin.", "err")
            return

        # Aracın sistemde kurulu olduğunu doğrula.
        if shutil.which(cmd[0]) is None:
            self.log(f"'{cmd[0]}' bulunamadı. Kurun: sudo apt install {cmd[0]}", "err")
            return

        # Wordlist dosyası gerçekten var mı? (-w kullanan araçlar)
        if "-w" in cmd:
            i = cmd.index("-w")
            wl_path = cmd[i + 1] if i + 1 < len(cmd) else ""
            if not os.path.isfile(wl_path):
                self.log(f"Wordlist bulunamadı: '{wl_path}'. 'Gözat' ile geçerli bir "
                         f"dosya seçin.", "err")
                return

        # Hedef biçimi kontrolü: profil url isterse http:// olmalı, domain isterse olmamalı.
        kind = profile.get("target_kind", "any")
        has_scheme = any(a.startswith(("http://", "https://")) for a in cmd)
        if kind == "url" and not has_scheme:
            self.log("Bu profil http:// veya https:// ile başlayan bir URL ister. "
                     "Hedefi öyle girin (örn. http://hedef).", "err")
            return
        if kind == "domain" and has_scheme:
            self.log("Bu profil ŞEMASIZ alan adı ister (http:// olmadan, örn. hedef.com).",
                     "err")
            return

        # Root gerektiren profil uyarısı (engellemez, sadece bilgilendirir).
        if profile.get("requires_root") and not is_root():
            self.log(self.cfg.root_warning, "warn")

        self._scan_start = time.monotonic()
        self._last_meta = (name, target or cmd[-1])
        self._has_results = False
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status.configure(text=f"Durum: '{name}' çalışıyor...")
        self.log(f"=== '{name}' başlatıldı — {target} ===", "info")

        self._worker = threading.Thread(target=self._run_command, args=(cmd,), daemon=True)
        self._worker.start()

    def on_stop(self):
        if self._proc and self._proc.poll() is None:
            self.log("Durdurma isteği gönderiliyor...", "warn")
            try:
                # Süreç grubunu sonlandır (start_new_session=True ile grup lideri yaptık).
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError) as e:
                self.log(f"Süreç durdurulamadı: {e}", "err")

    # ------------------------------------------------- Subprocess + Thread --
    def _run_command(self, cmd: list):
        """Ayrı thread'de çalışır. Popen ile satır satır canlı stdout okur."""
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,   # stderr'i de aynı akışa katıp göster
                text=True,
                bufsize=1,                  # satır tamponlaması (canlı akış)
                start_new_session=True,     # kendi süreç grubu -> temiz durdurma
            )
        except Exception as e:  # noqa: BLE001 (kullanıcıya hatayı göstermek istiyoruz)
            self._ui(self.log, f"Süreç başlatılamadı: {e}", "err")
            self._ui(self._reset_controls)
            return

        # Canlı çıktı okuma döngüsü. Çıktıyı ipucu için de biriktir (thread-güvenli).
        assert self._proc.stdout is not None
        captured = []
        for line in self._proc.stdout:
            self._ui(self.log, line.rstrip("\n"))
            self._has_results = True
            captured.append(line.lower())

        code = self._proc.wait()
        # Araca özel ek ipucu (örn. Nmap için -Pn önerisi).
        if self.cfg.output_hint:
            hint = self.cfg.output_hint(cmd, "".join(captured))
            if hint:
                self._ui(self.log, hint, "warn")

        elapsed = time.monotonic() - self._scan_start
        if code == 0:
            self._ui(self.log, f"=== Tamamlandı — süre {elapsed:.1f}sn ===", "ok")
        elif code < 0:
            self._ui(self.log, f"=== Durduruldu — süre {elapsed:.1f}sn ===", "warn")
        else:
            self._ui(self.log,
                     f"=== Bitti (çıkış kodu {code}) — süre {elapsed:.1f}sn ===", "warn")

        self._proc = None
        self._ui(self._reset_controls)
        if self.autosave_var.get():
            self._ui(self._autosave)

    # --------------------------------------------------------- Kaydetme --
    def _log_text(self) -> str:
        return self.log_box.get("1.0", "end").rstrip("\n")

    @staticmethod
    def _safe_name(text: str) -> str:
        """Dosya adı için güvenli hale getir (harf/rakam dışını _ yap)."""
        return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_") or "sonuc"

    def _default_filename(self) -> str:
        profile, target = self._last_meta
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{self._safe_name(profile)}_{self._safe_name(target)}_{stamp}.txt"

    def _autosave(self):
        """İşlem bitince results/ klasörüne otomatik yazar."""
        if not self._has_results:
            return
        try:
            self.cfg.results_dir.mkdir(parents=True, exist_ok=True)
            path = self.cfg.results_dir / self._default_filename()
            path.write_text(self._log_text(), encoding="utf-8")
            self.log(f"Sonuç kaydedildi: {path}", "ok")
        except OSError as e:
            self.log(f"Otomatik kaydetme başarısız: {e}", "err")

    def save_output(self):
        """Manuel kaydetme: kullanıcıya 'Farklı Kaydet' penceresi açar."""
        if not self._has_results:
            self.log(f"Kaydedilecek sonuç yok. Önce '{self.cfg.start_label}' ile "
                     f"bir işlem çalıştırın.", "warn")
            return
        rd = self.cfg.results_dir
        path = filedialog.asksaveasfilename(
            title="Sonucu Kaydet", defaultextension=".txt",
            initialdir=str(rd if rd.is_dir() else Path.home()),
            initialfile=self._default_filename(),
            filetypes=[("Metin dosyası", "*.txt"), ("Tüm dosyalar", "*.*")])
        if not path:
            return
        try:
            Path(path).write_text(self._log_text(), encoding="utf-8")
            self.log(f"Sonuç kaydedildi: {path}", "ok")
        except OSError as e:
            self.log(f"Kaydetme başarısız: {e}", "err")

    def open_results(self):
        """results/ klasörünü sistem dosya yöneticisinde açar."""
        try:
            self.cfg.results_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.log(f"Sonuçlar klasörü oluşturulamadı: {e}", "err")
            return
        opener = "xdg-open"
        if os.name == "nt":
            opener = "explorer"
        elif sys.platform == "darwin":
            opener = "open"
        try:
            subprocess.Popen([opener, str(self.cfg.results_dir)])
            self.log(f"Sonuçlar klasörü açıldı: {self.cfg.results_dir}", "info")
        except OSError as e:
            self.log(f"Klasör açılamadı ({e}). Yol: {self.cfg.results_dir}", "err")

    # ------------------------------------------------------------- Yardımcı --
    def _ui(self, fn, *args):
        """Fonksiyonu güvenli biçimde ana Tk thread'inde çalıştırır."""
        self.after(0, lambda: fn(*args))

    def _reset_controls(self):
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status.configure(text="Durum: Bekleniyor")

    def _on_close(self):
        if self._proc and self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
            except Exception:  # noqa: BLE001
                pass
        self.destroy()
