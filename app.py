#!/usr/bin/env python3
"""
KaliRecon — Nmap, Gobuster, ffuf ve WhatWeb GUI keşif otomasyonu.

Bu dosya yalnızca KaliRecon'a ÖZGÜ kısımları içerir: tarama profilleri ve ayarlar.
Ortak altyapı (tema, komut çalıştırıcı, canlı log, kaydetme, güvenlik) kali_core.py'de.

YASAL UYARI: Yalnızca sahibi olduğunuz veya yazılı izinli olduğunuz hedeflerde kullanın.
"""

from pathlib import Path

from kali_core import KaliToolApp, ToolConfig

# Tarama profilleri. Her profil alanları:
#   tool          : çalıştırılacak araç (nmap / gobuster / ffuf / whatweb)
#   args          : argüman listesi; {target} ve {wordlist} çalışma anında doldurulur
#   hint          : arayüzde beliren açıklama/uyarı
#   needs_wordlist: wordlist alanı gerekli mi
#   target_kind   : "any" (ip/host/url), "url" (http zorunlu), "domain" (şemasız alan adı)
#   requires_root : (opsiyonel) root/setcap gerekiyorsa True
SCAN_PROFILES = {
    # ----------------------------- NMAP ------------------------------------
    "Nmap — Hızlı Tarama (ilk keşif)": {
        "tool": "nmap",
        "args": ["-T4", "-F", "{target}"],
        "hint": "En yaygın 100 portu hızlıca tarar. Bir hedefe ilk baktığınızda "
                "hızlı genel görünüm için idealdir.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Tüm Portlar (-p-)": {
        "tool": "nmap",
        "args": ["-p-", "-T4", "{target}"],
        "hint": "65535 portun TAMAMINI tarar. Gizli/yüksek portlardaki servisleri "
                "bulur (CTF'de sık gerekir). Yavaştır ama kapsamlıdır.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Servis & Sürüm (-sV)": {
        "tool": "nmap",
        "args": ["-sV", "-T4", "{target}"],
        "hint": "Açık portlardaki servisleri ve sürüm numaralarını tespit eder. "
                "Zafiyet aramadan önce 'ne çalışıyor?' sorusunu yanıtlar.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Varsayılan Scriptler (-sC -sV)": {
        "tool": "nmap",
        "args": ["-sC", "-sV", "-T4", "{target}"],
        "hint": "Sürüm tespiti + güvenli NSE scriptlerini çalıştırır (banner, başlık, "
                "anonim FTP vb.). CTF keşfinde en çok kullanılan komuttur.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Ping'siz Tarama (-Pn)": {
        "tool": "nmap",
        "args": ["-Pn", "-T4", "{target}"],
        "hint": "ICMP (ping) engelleyen Windows/firewall'lı sistemler için idealdir. "
                "Host kapalı sanılsa bile taramaya devam eder.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Agresif (-A: OS+Script+Trace)": {
        "tool": "nmap",
        "args": ["-A", "-T4", "{target}"],
        "hint": "İşletim sistemi, sürüm, script ve traceroute'u birlikte yapar. "
                "Çok bilgi verir AMA çok gürültülüdür; IDS/IPS yakalar.",
        "needs_wordlist": False, "target_kind": "any", "requires_root": True,
    },
    "Nmap — İşletim Sistemi Tespiti (-O)": {
        "tool": "nmap",
        "args": ["-O", "{target}"],
        "hint": "Hedefin işletim sistemini tahmin eder. Root/setcap yetkisi ister. "
                "Windows mı Linux mu ayrımı için kullanışlıdır.",
        "needs_wordlist": False, "target_kind": "any", "requires_root": True,
    },
    "Nmap — UDP Hızlı Tarama": {
        "tool": "nmap",
        "args": ["-sU", "--top-ports", "20", "-T4", "{target}"],
        "hint": "En yaygın 20 UDP portunu tarar (DNS, SNMP, TFTP...). UDP taraması "
                "yavaştır; sadece üst portlarla sınırladık. Root/setcap ister.",
        "needs_wordlist": False, "target_kind": "any", "requires_root": True,
    },
    "Nmap — Zafiyet Scriptleri (--script vuln)": {
        "tool": "nmap",
        "args": ["-sV", "--script", "vuln", "-T4", "{target}"],
        "hint": "Bilinen zafiyetleri arayan NSE scriptlerini çalıştırır. Kolay "
                "kazançlar (low-hanging fruit) için iyidir ama yanlış pozitif verebilir.",
        "needs_wordlist": False, "target_kind": "any",
    },
    # ----------------- NMAP KOMBO (pentest paketleri) ----------------------
    "Nmap — Kapsamlı (Tüm Port + Script + Sürüm)": {
        "tool": "nmap",
        "args": ["-p-", "-sC", "-sV", "-T4", "{target}"],
        "hint": "TEK KOMUTLA tam keşif: 65535 portu tarar + servis sürümlerini + "
                "varsayılan scriptleri çalıştırır. Pentest/CTF'de en çok istenen komut. "
                "Yavaştır ama en eksiksiz sonucu verir.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Script + Sürüm + OS Tespiti": {
        "tool": "nmap",
        "args": ["-sC", "-sV", "-O", "-T4", "{target}"],
        "hint": "Servis sürümü + varsayılan scriptler + işletim sistemi tespitini "
                "birlikte yapar. Hedefi hızlıca profillemek için idealdir. Root ister.",
        "needs_wordlist": False, "target_kind": "any", "requires_root": True,
    },
    "Nmap — Hızlı Tam Port (--min-rate 10000)": {
        "tool": "nmap",
        "args": ["-p-", "--min-rate", "10000", "-T4", "{target}"],
        "hint": "65535 portu YÜKSEK HIZDA tarar (yalnızca açık portları bulur). "
                "Önce bununla portları bulup sonra o portlara -sC -sV atmak yaygın "
                "pentest taktiğidir. Gürültülüdür.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Windows/Firewall (-Pn + Script + Sürüm)": {
        "tool": "nmap",
        "args": ["-Pn", "-sC", "-sV", "-T4", "{target}"],
        "hint": "Windows hedefler ve ping'i (ICMP) engelleyen firewall'lar için. "
                "Nmap 'Host seems down' derse veya hiç port bulamazsanız bu profili "
                "kullanın: -Pn ping kontrolünü atlar, script+sürüm birlikte çalışır.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Ağ Keşfi / Canlı Host (-sn)": {
        "tool": "nmap",
        "args": ["-sn", "{target}"],
        "hint": "Bir ağdaki AYAKTA olan cihazları bulur (port taramaz). Hedefe bir "
                "aralık/CIDR girin: örn. 192.168.1.0/24. Her pentest'in ilk adımıdır.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Belirli Portlar (-p, düzenleyin)": {
        "tool": "nmap",
        "args": ["-p", "80,443,8080,8443", "-sV", "{target}"],
        "hint": "Yalnızca belirtilen portları tarar. Komut satırındaki port listesini "
                "(80,443,...) elle düzenleyip istediğiniz portları yazabilirsiniz.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Top 1000 + Script + Sürüm": {
        "tool": "nmap",
        "args": ["-sC", "-sV", "--top-ports", "1000", "-T4", "{target}"],
        "hint": "En yaygın 1000 portu script+sürüm ile tarar. Hız/kapsam dengesi iyi; "
                "'Kapsamlı' (-p-) kadar yavaş olmadan ciddi bilgi verir.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Servis Enum (FTP/SMB/HTTP NSE)": {
        "tool": "nmap",
        "args": ["-sV", "--script",
                 "ftp-anon,smb-enum-shares,smb-os-discovery,http-enum", "-T4", "{target}"],
        "hint": "Servis-özel NSE scriptleri: anonim FTP, SMB paylaşımları/OS, HTTP dizin "
                "keşfi. CTF'de servislerden hızlı bilgi toplamak için birebir.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "Nmap — Gizli/Firewall Atlatma (-sS -T2 -f)": {
        "tool": "nmap",
        "args": ["-sS", "-T2", "-f", "{target}"],
        "hint": "Yavaş (-T2) SYN taraması + paket parçalama (-f) ile IDS/IPS'ten kaçınmaya "
                "çalışır. Ham soket için root ister. Gürültüden kaçınmak gerektiğinde.",
        "needs_wordlist": False, "target_kind": "any", "requires_root": True,
    },
    # --------------------------- GOBUSTER ----------------------------------
    "Gobuster — Dizin Keşfi": {
        "tool": "gobuster",
        "args": ["dir", "-u", "{target}", "-w", "{wordlist}", "-q", "--no-progress"],
        "hint": "Web sunucusunda gizli dizin/dosya arar (/admin, /backup...). "
                "Hedef http:// veya https:// ile başlamalı. Wordlist gerekir.",
        "needs_wordlist": True, "target_kind": "url",
    },
    "Gobuster — Dizin + Uzantılar (php,html,txt)": {
        "tool": "gobuster",
        "args": ["dir", "-u", "{target}", "-w", "{wordlist}",
                 "-x", "php,html,txt,bak", "-q", "--no-progress"],
        "hint": "Dizinlere ek olarak belirtilen uzantılı dosyaları da dener "
                "(index.php, config.bak...). Web CTF'lerinde çok verimlidir.",
        "needs_wordlist": True, "target_kind": "url",
    },
    "Gobuster — Alt Alan Adı (DNS)": {
        "tool": "gobuster",
        "args": ["dns", "--domain", "{target}", "-w", "{wordlist}", "-q", "--no-progress"],
        "hint": "Alt alan adlarını bulur (mail.hedef.com, dev.hedef.com...). "
                "Hedef ŞEMASIZ alan adı olmalı (örn: hedef.com). Subdomain wordlist'i kullanın.",
        "needs_wordlist": True, "target_kind": "domain",
    },
    "Gobuster — Sanal Host (vhost)": {
        "tool": "gobuster",
        "args": ["vhost", "-u", "{target}", "-w", "{wordlist}", "-q", "--no-progress", "--append-domain"],
        "hint": "Aynı IP üzerindeki gizli sanal hostları bulur. HTB/CTF'de aynı "
                "sunucuda saklı siteleri ortaya çıkarır. Hedef http:// ile başlamalı.",
        "needs_wordlist": True, "target_kind": "url",
    },
    "Gobuster — HTTPS + Yönlendirme (-k -r)": {
        "tool": "gobuster",
        "args": ["dir", "-u", "{target}", "-w", "{wordlist}", "-k", "-r", "-q", "--no-progress"],
        "hint": "Geçersiz TLS sertifikasını yok sayar (-k) ve yönlendirmeleri takip eder "
                "(-r). Self-signed HTTPS kullanan CTF/lab hedeflerinde gereklidir.",
        "needs_wordlist": True, "target_kind": "url",
    },
    # ------------------------------ FFUF -----------------------------------
    "ffuf — Dizin Fuzzing": {
        "tool": "ffuf",
        "args": ["-u", "{target}/FUZZ", "-w", "{wordlist}", "-s"],
        "hint": "Hızlı dizin/dosya keşfi. Hedef http:// ile başlamalı (sonuna / KOYMAYIN; "
                "/FUZZ otomatik eklenir). Wordlist gerekir.",
        "needs_wordlist": True, "target_kind": "url",
    },
    "ffuf — Uzantılı Dizin Fuzzing (-e)": {
        "tool": "ffuf",
        "args": ["-u", "{target}/FUZZ", "-w", "{wordlist}",
                 "-e", ".php,.html,.txt,.bak", "-s"],
        "hint": "Dizinlere ek olarak uzantılı dosyaları da dener. Uzantı listesini "
                "(-e sonrası) komut satırında düzenleyebilirsiniz.",
        "needs_wordlist": True, "target_kind": "url",
    },
    "ffuf — Parametre Fuzzing (GET ?FUZZ=)": {
        "tool": "ffuf",
        "args": ["-u", "{target}/?FUZZ=deneme", "-w", "{wordlist}", "-s"],
        "hint": "Gizli GET parametrelerini bulur (?id=, ?debug=...). Web CTF'de gizli "
                "işlevleri ortaya çıkarır. Parametre değerini komuttan düzenleyebilirsiniz.",
        "needs_wordlist": True, "target_kind": "url",
    },
    "ffuf — Vhost Fuzzing (Host başlığı)": {
        "tool": "ffuf",
        "args": ["-u", "{target}", "-H", "Host: FUZZ.hedef.local",
                 "-w", "{wordlist}", "-s"],
        "hint": "Sanal hostları Host başlığını fuzzlayarak bulur. 'FUZZ.hedef.local' "
                "kısmını gerçek alan adınıza göre komut satırında düzenleyin.",
        "needs_wordlist": True, "target_kind": "url",
    },
    # ----------------------------- WHATWEB ---------------------------------
    "WhatWeb — Hızlı Parmak İzi": {
        "tool": "whatweb",
        "args": ["{target}"],
        "hint": "Hedef web teknolojilerini tespit eder (CMS, sunucu, sürüm, framework). "
                "Hızlı ve gürültüsüz keşif. Hedef URL ya da IP olabilir.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "WhatWeb — Detaylı (-v)": {
        "tool": "whatweb",
        "args": ["-v", "{target}"],
        "hint": "Ayrıntılı çıktı: bulunan her eklenti/teknoloji için açıklama ve "
                "sertifika/başlık bilgisi. Rapor için daha zengin veri verir.",
        "needs_wordlist": False, "target_kind": "any",
    },
    "WhatWeb — Agresif (-a 3)": {
        "tool": "whatweb",
        "args": ["-a", "3", "{target}"],
        "hint": "Agresiflik seviyesi 3: daha fazla istek göndererek daha çok teknoloji "
                "tespit eder. Biraz daha gürültülüdür ama derin parmak izi çıkarır.",
        "needs_wordlist": False, "target_kind": "any",
    },
}

# Kali'de yaygın wordlist adayları (ilk bulunan otomatik seçilir).
DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]


def nmap_pn_hint(cmd: list, output_lower: str) -> str | None:
    """Nmap 'host down' belirtileri görürse -Pn önerir (araca özel ipucu)."""
    if "-Pn" in cmd:
        return None
    if any(s in output_lower for s in ("host seems down", "0 hosts up", "try -pn")):
        return ("İPUCU: Hedef ping'e (ICMP) yanıt vermiyor olabilir — Windows ya da "
                "firewall'lı sistemlerde tipiktir. 'Nmap — Windows/Firewall (-Pn ...)' "
                "profiliyle tekrar deneyin; -Pn ping kontrolünü atlar.")
    return None


CONFIG = ToolConfig(
    app_name="KaliRecon",
    window_title="KaliRecon — Nmap, Gobuster, ffuf, WhatWeb",
    subtitle="Keşif & Bilgi Toplama Otomasyonu",
    profiles=SCAN_PROFILES,
    tools=["Nmap", "Gobuster", "ffuf", "WhatWeb"],
    allowed_tools={"nmap", "gobuster", "ffuf", "whatweb"},
    results_dir=Path(__file__).resolve().parent / "results",
    default_wordlists=DEFAULT_WORDLISTS,
    wordlist_label="Wordlist (Gobuster / ffuf)",
    start_label="Taramayı Başlat",
    ready_msg="KaliRecon hazır.",
    root_warning=("Bu profil root yetkisi ister. Root değilseniz eksik/hatalı sonuç "
                  "alabilirsiniz. Öneri: sudo setcap cap_net_raw,cap_net_admin+eip "
                  "$(command -v nmap)"),
    output_hint=nmap_pn_hint,
)


def main():
    KaliToolApp(CONFIG).mainloop()


if __name__ == "__main__":
    main()
