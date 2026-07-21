# KaliRecon

Kali Linux için basit bir tarama arayüzü. **Nmap, Gobuster, ffuf ve WhatWeb**'i tek
pencereden, komut ezberlemeden çalıştırırsınız.

Terminale uzun parametreler yazmak yerine bir profil seçersiniz (örneğin "Hızlı Tarama"
ya da "Windows için Ping'siz Tarama"), araç doğru komutu kendisi kurar ve çalıştırır.
Sonuçlar canlı olarak ekrana akar ve otomatik kaydedilir.

> **Uyarı:** Sadece kendi sistemlerinizde veya izin aldığınız hedeflerde kullanın.
> İzinsiz tarama suçtur.

---

## Kurulum (Kali)

```bash
git clone https://github.com/lBurak1/KaliRecon.git
cd KaliRecon
chmod +x install.sh run.sh
./install.sh        # gerekli araçları ve sanal ortamı kurar
./run.sh            # uygulamayı başlatır
```

## Nasıl kullanılır

1. **Araç** seç: Nmap, Gobuster, ffuf veya WhatWeb
2. **Hedef** yaz: IP veya URL (örn. `scanme.nmap.org`)
3. **Profil** seç — yanında ne işe yaradığı yazar
4. **Taramayı Başlat** — çıktı ekrana akar, `results/` klasörüne kaydedilir

Gobuster/ffuf profillerinde bir **kelime listesi** (wordlist) gerekir; "Gözat" ile
seçebilirsiniz. Oluşan komutu çalıştırmadan önce elle de düzenleyebilirsiniz.

---

## İçindeki araçlar

- **Nmap** — port ve servis taraması (18 profil: hızlı, kapsamlı, ağ keşfi, zafiyet vb.)
- **Gobuster** — gizli dizin ve alt alan adı keşfi
- **ffuf** — hızlı web fuzzing (dizin, parametre, vhost)
- **WhatWeb** — hedefin kullandığı teknolojileri tespit

## Notlar

- Bazı Nmap taramaları (`-sS`, `-O`, `-sU`) root ister:
  `sudo setcap cap_net_raw,cap_net_admin+eip $(command -v nmap)`
- Uygulamayı root ile açmayın (arayüz sorunları çıkabilir).
- Güvenli test hedefi: `scanme.nmap.org` (Nmap'in izinli test sunucusu).

---

*Eğitim ve yetkili güvenlik testi içindir.*
