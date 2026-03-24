# Octopus — Codebase Dokümantasyonu

> **Son güncelleme:** Mart 2026 (v2 — Extreme/Ruijie tam destek)  
> Bu dosya, projenin tüm modüllerini, veri akışlarını, desteklenen cihaz tiplerini ve bilinen sorunları belgeler.

---

## İçindekiler

1. [Proje Yapısı](#1-proje-yapısı)
2. [Veri Dosyaları](#2-veri-dosyaları)
3. [Web Katmanı — `web.py`](#3-web-katmanı--webpy)
4. [Dynamic Inventory Scan](#4-dynamic-inventory-scan)
5. [Inventory Collector](#5-inventory-collector)
6. [Desteklenen Cihaz Tipleri](#6-desteklenen-cihaz-tipleri)
7. [Parser Katmanı](#7-parser-katmanı)
8. [Network Backup](#8-network-backup)
9. [Password Manager / Vault](#9-password-manager--vault)
10. [Geçmiş Buglar ve Düzeltmeler](#10-geçmiş-buglar-ve-düzeltmeler)
11. [Yeni Cihaz Tipi Ekleme Rehberi](#11-yeni-cihaz-tipi-ekleme-rehberi)

---

## 1. Proje Yapısı

```
octopus/
├── app/
│   ├── web.py                          # Flask API + tüm UI (tek dosya SPA)
│   ├── main.py                         # CLI entry point
│   ├── common/
│   │   ├── vault_helper.py             # Vault yükleme yardımcıları
│   │   └── vault_utils.py
│   ├── core/
│   │   ├── base_module.py              # Tüm modüllerin base class'ı
│   │   ├── logging_setup.py
│   │   └── module_loader.py
│   ├── data/                           # JSON veri dosyaları (runtime)
│   │   ├── inventory.json              # Ana cihaz envanteri
│   │   ├── device_details.json         # Collector'dan gelen detaylı bilgiler
│   │   ├── device_status.json          # Cihaz durumu (up/down/warn)
│   │   ├── users.json
│   │   ├── commands.json
│   │   ├── exclude.json                # Taramadan hariç tutulacak IP'ler
│   │   └── backup_schedule.json
│   └── modules/
│       ├── dynamic_inventory_scan/     # Ağ tarama motoru
│       │   ├── service.py              # ← ANA MOTOR
│       │   ├── module.py               # CLI arayüzü
│       │   └── mac_vendor.py           # OUI/MAC vendor lookup
│       ├── inventory_collector/        # SSH envanter toplama
│       │   ├── module.py               # ← DISPATCH + COLLECT FONKSİYONLARI
│       │   ├── parser.py               # Eski parser wrapper (kullanılmıyor)
│       │   └── parsers/
│       │       ├── __init__.py         # get_parser() router
│       │       ├── cisco.py            # IOS, IOS-XE, NX-OS, AP
│       │       ├── huawei.py
│       │       ├── hp_comware.py       # HP Comware + H3C
│       │       ├── extreme.py          # Extreme Networks ExtremeXOS  ← YENİ
│       │       ├── ruijie.py           # Ruijie RGOS                  ← YENİ
│       │       ├── fortigate.py        # FortiGate REST
│       │       ├── fortinet_ssh.py     # FortiAnalyzer/Manager SSH
│       │       ├── f5.py               # F5 BIG-IP REST
│       │       └── dell_force10.py
│       ├── network_backup/             # Cihaz config backup
│       ├── network_map/                # Topoloji haritası
│       └── password_manager/           # Vault (credential store)
├── requirements.txt
└── CODEBASE.md                         # Bu dosya
```

---

## 2. Veri Dosyaları

### `inventory.json`
Ana cihaz listesi. Her kayıt:

```json
{
  "name": "SW-CORE-01",
  "ip": "10.0.0.1",
  "device_type": "cisco_ios",
  "credential_id": "cisco-cred-01",
  "tags": ["all", "discovered", "subnet_10_0_0", "cisco"],
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "serial_no": "FOC1234ABCD",
  "port": 22,
  "discovered_at": "2025-01-01 10:00:00",
  "additional_ips": []
}
```

**Geçerli `device_type` değerleri** (Netmiko platform isimleri):

| Değer | Marka | Bağlantı Yöntemi |
|---|---|---|
| `cisco_ios` | Cisco IOS/IOS-XE | Netmiko |
| `cisco_nxos` | Cisco NX-OS (Nexus) | Netmiko |
| `cisco_ap` | Cisco Access Point | Netmiko |
| `huawei` | Huawei VRP | Netmiko |
| `h3c_comware` | H3C Comware | Netmiko |
| `hp_comware` | HP Comware | Netmiko |
| `extreme_exos` | Extreme Networks ExtremeXOS | **Paramiko** (direkt) |
| `ruijie_os` | Ruijie Networks RGOS | **Paramiko** (direkt) |
| `fortigate` | FortiGate | REST API |
| `fortianalyzer` | FortiAnalyzer | Paramiko interactive shell |
| `fortimanager` | FortiManager | Paramiko interactive shell |
| `bigip` / `f5` | F5 BIG-IP | REST API |
| `dell_force10` | Dell Force10 | Netmiko |

> **ÖNEMLİ:** `extreme_exos` ve `ruijie_os` Netmiko yerine doğrudan paramiko kullanır.
> `_collect_extreme()` ve `_collect_ruijie()` fonksiyonları paramiko interactive shell ile bağlanır.

### `device_details.json`
`inventory_collector` çalıştığında doldurulan detay verisi. IP bazlı dict:

```json
{
  "10.0.0.1": {
    "device": "SW-CORE-01",
    "ip": "10.0.0.1",
    "brand": "Cisco",
    "model": "WS-C3560CX-12PD-S",
    "hostname": "SW-CORE-01",
    "serial_no": "FOC2530LXTS",
    "software_version": "15.2(7)E11",
    "uptime": "42 weeks, 18 hours",
    "collected_hostname": "SW-CORE-01",
    "last_collected": "2025-03-01 10:00:00"
  }
}
```

---

## 3. Web Katmanı — `web.py`

Flask tabanlı tek dosya SPA. Hem API endpoint'lerini hem de tüm HTML/CSS/JS'yi içerir.

### Önemli API Endpoint'leri

| Endpoint | Metod | Açıklama |
|---|---|---|
| `/api/login` | POST | Kullanıcı girişi |
| `/api/stats` | GET | Marka/model/tag istatistikleri |
| `/api/inventory` | GET | Tüm inventory listesi |
| `/api/inventory` (POST via `/api/inv/add`) | POST | Cihaz ekle |
| `/api/inv/<idx>` | PUT/DELETE | Cihaz güncelle/sil |
| `/api/scan/start` | POST | IP tarama başlat |
| `/api/collector/start` | POST | Envanter toplama başlat |
| `/api/device/<idx>` | GET | Cihaz detayı |
| `/api/device/<idx>/collect` | POST | Tekil envanter al |
| `/api/job/<job_id>` | GET | Async iş durumu |
| `/api/device-details` | GET | Tüm device_details.json |
| `/api/notifications/stream` | GET | SSE bildirim akışı |

### Brand Tespiti (Stats endpoint, ~1694. satır)

```python
brand = ("Fortinet"         if "forti"   in dt else
         "Cisco"            if "cisco"   in dt else
         "Huawei"           if "huawei"  in dt else
         "H3C"              if "h3c"     in dt or "comware" in dt else
         "Extreme Networks" if "extreme" in dt else
         "Ruijie"           if "ruijie"  in dt or "rgos" in dt else
         "F5"               if "f5"      in dt or "bigip" in dt else
         "Dell"             if "dell"    in dt else
         "HP"               if "hp"      in dt else dt.title())
```

### Brand Kolonu (Inventory tablosu, ~3876. satır)

`device_details.json`'da `brand` alanı varsa onu kullanır, yoksa `device_type`'tan türetir:

```javascript
{h:'Brand', f:d=>{
  if(details[d.ip]?.brand) return details[d.ip].brand;
  const dt=(d.device_type||'').toLowerCase();
  if(dt.includes('ruijie')||dt.includes('rgos')) return 'Ruijie';
  if(dt.includes('extreme')) return 'Extreme Networks';
  // ... diğer markalar
}}
```

### Cihaz Tipi Dropdown (`mi-type` select, ~2950. satır)

```html
<select id="mi-type">
  <option>cisco_ios</option><option>cisco_nxos</option><option>cisco_ap</option>
  <option>huawei</option><option>dell_force10</option>
  <option>hp_comware</option><option>hp_procurve</option><option>h3c_comware</option>
  <option>extreme_exos</option><option>ruijie_os</option>
  <option>fortigate</option><option>fortianalyzer</option><option>fortimanager</option>
  <option>fortiauthenticator</option><option>fortisandbox</option>
  <option>bigip</option><option>velos_sc</option><option>velos_partition</option>
  <option>unknown</option>
</select>
```

---

## 4. Dynamic Inventory Scan

**Dosya:** `app/modules/dynamic_inventory_scan/service.py`

### Tarama Akışı (`scan_single`)

```
1. is_alive(ip)          → TCP ping (22/80/443/8080/8443) veya ICMP
2. ip in known_ips?      → zaten kayıtlıysa atla
3. scan_ports(ip)        → [22, 80, 443, 3389] aç mı kontrol
4. get_mac_address()     → FortiGate ARP API → yerel arp -n
5. mac_vendor.lookup()   → OUI tablosu + macvendors.com API
6. 22 açıksa:
   try_ssh_credentials() → vault'taki tüm credential'lar denenir
   _detect_device_type_ssh() → show version / display version / interactive shell
   _classify_device_type()   → çıktı içeriğinden gerçek tipi tespit
   _get_serial_via_ssh()     → show version'dan serial
   add_to_inventory()        → inventory.json'a ekle
```

### Cihaz Tipi Tespiti (`_classify_device_type`)

`show version` / `display version` çıktısını analiz eder:

```python
def _classify_device_type(output: str, initial_type: str) -> str:
    # H3C Comware: "H3C Comware Software" veya "comware" + "h3c Sxxx"
    → "h3c_comware"
    # ExtremeXOS: "ExtremeXOS" veya "Extreme Networks"
    → "extreme_exos"
    # Ruijie RGOS: "ruijie" veya "rgos"
    → "ruijie_os"
    # NX-OS: "nx-os" veya "nxos"
    → "cisco_nxos"
    # Diğer: initial_type değişmeden döner
```

### Hostname Çıkarma (`_extract_hostname`)

| Cihaz | Pattern |
|---|---|
| Cisco NX-OS | `Device name: HOSTNAME` |
| Cisco IOS | `HOSTNAME uptime is ...` ("Kernel" hariç) |
| Huawei / H3C | `<HOSTNAME>` prompt |
| Extreme | `SysName: HOSTNAME` |
| Ruijie | `HOSTNAME#` prompt |
| FortiGate | `Hostname: HOSTNAME` |

### Interactive Shell Fallback

`exec_command` ile cevap alınamazsa (Extreme, Ruijie gibi cihazlar):

```python
# Banner okunur → içerik analiz edilir
if "extremexos" in banner: → show switch → "extreme_exos"
if "ruijie" in banner:     → show version → "ruijie_os"
# Sonra FortiGate denenir
get system status → "fortigate"
```

### `add_to_inventory` — Deduplication Önceliği

1. **MAC adresi** eşleşmesi → aynı cihaz, IP güncelle
2. **Serial numarası** eşleşmesi → aynı cihaz, IP güncelle
3. **IP** eşleşmesi → mevcut kaydı MAC/serial ile zenginleştir, atla
4. Hiçbiri yoksa → yeni kayıt oluştur

### `_build_device_name` — Prefix Haritası

```python
prefix_map = {
    "cisco":   "CISCO",
    "huawei":  "HUAWEI",
    "fortigate": "FGT",
    "h3c":     "H3C",
    "extreme": "EXT",
    "ruijie":  "RJ",
    "unknown": "DEVICE",
}
# Örnek: 10.1.2.3 + ruijie_os → "RJ_2_3"
```

---

## 5. Inventory Collector

**Dosya:** `app/modules/inventory_collector/module.py`

### Dispatch Akışı (`_collect_single`)

```
device_type
    ├─ fortianalyzer/fortimanager/...  → _collect_fortinet_ssh()  [paramiko]
    ├─ fortigate                       → _collect_fortigate()      [REST API]
    ├─ f5 / bigip                      → _collect_f5()             [REST API]
    ├─ ruijie / ruijie_os / rgos       → _collect_ruijie()         [paramiko] ← ÖNEMLİ
    ├─ extreme / extreme_exos          → _collect_extreme()        [paramiko] ← ÖNEMLİ
    └─ diğer (cisco/huawei/h3c/...)    → _collect_ssh()            [Netmiko]
```

> **Neden Ruijie ve Extreme paramiko kullanır?**  
> Netmiko `ruijie_os` ve `extreme_exos` driver'ları bu cihazların SSH prompt'larıyla
> uyumsuzluk yaşıyordu. Paramiko interactive shell ile doğrudan bağlantı %100 çalışıyor.

### `_classify_output` — Yanlış device_type Düzeltme

Envanter alınırken `device_type` yanlış kaydedilmiş olsa bile çıktı içeriğine bakarak doğru parser seçilir:

```python
def _classify_output(output: str, current_type: str) -> str:
    # "Ruijie" veya "RGOS" varsa → "ruijie_os"
    # "ExtremeXOS" varsa        → "extreme_exos"
    # "H3C Comware" varsa       → "h3c_comware"
    # "NX-OS" varsa             → "cisco_nxos"
    # "VRP" varsa               → "huawei"
```

**Pratik sonuç:** Cihaz `cisco_ios` olarak kaydedilmiş olsa bile Ruijie çıktısı gelirse `parse_ruijie` çağrılır.

### `_netmiko_type` — Netmiko Platform Normalizasyonu

```python
_NETMIKO_TYPE_MAP = {
    "extreme_exos":  "extreme_exos",
    "extreme_xos":   "extreme_exos",   # eski tip adı
    "extreme_os":    "extreme_exos",   # kullanıcı hatası
    "extreme":       "extreme_exos",
    "ruijie_os":     "ruijie_os",
    "ruijie":        "ruijie_os",
    "rgos":          "ruijie_os",
    "h3c_comware":   "h3c_comware",
    "hp_comware":    "hp_comware",
    "cisco_nxos":    "cisco_nxos",
}
```

### Komut Haritası (`_collect_ssh`)

| `device_type` | `cmd_version` | `cmd_extra` |
|---|---|---|
| `cisco_*` | `show version` | `show inventory` |
| `huawei` | `display version` | `display device elabel brief` |
| `dell_force10` | `show version` | `show inventory` |
| `h3c_comware`, `hp_comware` | `display version` | `display device manuinfo` |
| `extreme_exos` | `show switch` | `show version` |
| `ruijie_os` | `show version` | *(yok)* |

### `_collect_ruijie` — Paramiko Akışı

```
paramiko bağlan → invoke_shell → banner oku → "show version\n" gönder
→ parse_ruijie(version_out) → result_data
```

### `_collect_extreme` — Paramiko Akışı

```
paramiko bağlan → invoke_shell → banner oku
→ "show switch\n"  gönder → switch_out
→ "show version\n" gönder → version_out
→ parse_extreme(switch_out, version_out) → result_data
```

---

## 6. Desteklenen Cihaz Tipleri

### Cisco

| Alt Tip | `device_type` | Komutlar | Parser |
|---|---|---|---|
| IOS / IOS-XE | `cisco_ios` | show version, show inventory | `parse_cisco` |
| NX-OS (Nexus) | `cisco_nxos` | show version, show inventory | `parse_cisco` |
| Access Point | `cisco_ap` | show version | `parse_cisco_ap` |

**Hostname kaynağı:**
- IOS: `HOSTNAME uptime is ...` satırı
- NX-OS: `Device name: HOSTNAME` satırı (öncelikli)

**Model kaynağı (fallback sırası):**
1. `show inventory` → `NAME: "Chassis"` / PID
2. `show inventory` → `NAME: "Switch N"` (stack)
3. `show version` → `Model number: WS-C3560CX-12PD-S`
4. `show version` → `cisco WS-C3560CX-12PD-S (APM...)` satırı
5. `show version` → Switch tablosu `* 1 18 WS-C3560CX-12PD-S`

### H3C (HP Comware)

| `device_type` | Komutlar | Parser |
|---|---|---|
| `h3c_comware` / `hp_comware` | display version, display device manuinfo | `parse_hp_comware` |

**Brand ayrımı:** `"h3c comware"` ifadesi varsa `brand="H3C"`, yoksa `brand="HP/H3C Comware"`

**Model kaynağı (fallback sırası):**
1. `H3C MODELNAME uptime is` satırı
2. `BOARD TYPE: MODELNAME`
3. `Product name: HP MODELNAME`
4. Generic `HP/H3C MODELNAME` referansı

### Extreme Networks ExtremeXOS

| `device_type` | Komutlar | Parser | Bağlantı |
|---|---|---|---|
| `extreme_exos` | show switch (version_out), show version (extra_out) | `parse_extreme` | **Paramiko** |

**Alan kaynakları:**
- Model: `System Type: X440G2-24p-10G4`
- Hostname: `SysName: MCN_UPS_SW`
- Version: `Primary ver: 30.7.1.1`
- Serial: `show version` → `Switch: 800616-00-22 2129G-00558` (2. alan)
- MAC: `System MAC: 00:04:96:FD:66:B7`

### Ruijie Networks RGOS

| `device_type` | Komutlar | Parser | Bağlantı |
|---|---|---|---|
| `ruijie_os` | show version | `parse_ruijie` | **Paramiko** |

**Alan kaynakları:**
- Model: `System description: ...(S6220-48XS6QXS-H)...`
- Hostname: `MACUNKOY_VM_RJ#` prompt
- Version: `System software version: S6220_RGOS 11.0(5)B9P33`
- Serial: `System serial number: G1NTAYD101243`
- Modules: `Slot 1/0`, `Slot 2/0`

### FortiGate

- `device_type`: `fortigate`
- **Bağlantı:** REST API (HTTPS)
- **Auth:** API Token veya username/password

### Fortinet SSH Ürünleri

- `device_type`: `fortianalyzer`, `fortimanager`, `fortiauthenticator`, `fortisandbox`
- **Bağlantı:** Paramiko interactive shell
- **Komut:** `get system status`

### F5 BIG-IP

- `device_type`: `bigip`, `f5`, `big-ip`
- **Bağlantı:** REST API (iControl REST)

---

## 7. Parser Katmanı

**Dosya:** `app/modules/inventory_collector/parsers/__init__.py`

### `get_parser(device_type)` Routing

```python
"huawei"           → parse_huawei
"cisco_ap"         → parse_cisco_ap
"cisco"            → parse_cisco
"dell_force10"     → parse_dell_force10
"h3c_comware" / "hp_comware" / "h3c" → parse_hp_comware
"extreme_exos" / "extreme"           → parse_extreme
"ruijie_os" / "ruijie" / "rgos"      → parse_ruijie
"fortigate"        → parse_fortigate
"fortianalyzer"... → parse_fortinet_ssh
"bigip" / "f5"     → parse_f5
```

### Parser Dönüş Alanları

Tüm parser'lar şu alanları döndürmeye çalışır (mevcut değilse `None`):

| Alan | Açıklama |
|---|---|
| `brand` | Marka adı (`"Cisco"`, `"H3C"`, `"Ruijie Networks"`, ...) |
| `model` | Model numarası (`"WS-C3560CX-12PD-S"`, `"S9820-64H"`, ...) |
| `hostname` | Cihazın kendi hostname'i |
| `serial_no` | Seri numarası |
| `software_version` | Yazılım versiyonu |
| `uptime` | Çalışma süresi |

`module.py` bu alanları `device_details.json`'a yazar. `web.py` de `collected_hostname` alanını hostname farkı tespitinde kullanır.

---

## 8. Network Backup

**Dosya:** `app/modules/network_backup/service.py`

Cihazlardan `show running-config` / `display current-configuration` çekerek dosya sistemi veya zamanlanmış görev olarak kaydeder.

---

## 9. Password Manager / Vault

**Dosya:** `app/modules/password_manager/`

Credential'lar (username, password, API token) şifreli olarak saklanır. Her cihaz kaydında `credential_id` alanı bu vault'taki bir kimlik bilgisine işaret eder.

---

## 10. Geçmiş Buglar ve Düzeltmeler

### 10.1 `Kernel` Hostname Hatası (NX-OS)

**Dosya:** `dynamic_inventory_scan/service.py` → `_extract_hostname`  
**Dosya:** `inventory_collector/parsers/cisco.py` → `parse_cisco`

**Sorun:** `show version` çıktısında `Kernel uptime is 519 day(s)...` satırı `^(\S+)\s+uptime` regex'i tarafından yakalanıyor, hostname `"Kernel"` olarak kaydediliyordu.

**Düzeltme:**
1. `Device name: HOSTNAME` satırı her zaman önce kontrol edilir (NX-OS)
2. `uptime is` regex'ine `(?!Kernel\b)` negative lookahead eklendi
3. `_HOSTNAME_BLACKLIST = {"cisco", "the", "switch", "router", "kernel"}` eklendi

---

### 10.2 `inv_status` UnboundLocalError

**Dosya:** `web.py` → `on_result` callback (~1269. satır)

**Sorun:** `line += f"... inv={inv_status}"` satırı `if res.ssh_success:` bloğunun dışındaydı. SSH başarısız olduğunda `inv_status` tanımsız kalıyordu.

**Düzeltme:** `line +=` satırı `if` bloğunun içine alındı (4 boşluk girinti).

---

### 10.3 C3560CX Model Bilgisi Yok

**Dosya:** `inventory_collector/parsers/cisco.py` → `parse_cisco`

**Sorun:** Model yalnızca `show inventory` çıktısından alınıyordu. C3560CX gibi bazı IOS cihazlarda `show inventory` anlamlı PID döndürmüyor.

**Düzeltme:** `show version` tabanlı 3 kademeli fallback eklendi:
1. `Model number: WS-C3560CX-12PD-S`
2. `cisco WS-C3560CX-12PD-S (APM...)` satırı
3. Switch tablosunda `* 1 18 WS-C3560CX-12PD-S`

---

### 10.4 H3C / Extreme / Ruijie Cisco Olarak Görünüyordu

**Sorun:** Bu markalar `show version` veya `display version`'a yanıt verdiği için `cisco_ios` veya `huawei` olarak etiketleniyordu.

**Düzeltme:**
- `_classify_device_type()` fonksiyonu eklendi: çıktı içeriğine göre tip rafine edilir
- `h3c_comware`, `extreme_exos`, `ruijie_os` Netmiko platform isimleri kullanılır
- `hp_comware.py`: H3C brand ayrımı, version regex genişletildi, patch_version alanı
- `extreme.py`: Yeni parser — `parse_extreme(switch_out, version_out)`
- `ruijie.py`: Yeni parser — `parse_ruijie(version_out)`

---

### 10.5 Extreme ve Ruijie "Desteklenmeyen SSH Tipi" Hatası

**Sorun 1 — Komut dispatch eksikti:** `_collect_ssh()` içindeki if/elif zincirinde Ruijie ve Extreme dalları yoktu. Her iki tip de `else` bloğuna düşüp hata dönüyordu.

**Sorun 2 — Extreme `unknown` kaydediliyordu:** `_DETECT_CMDS` listesinde `show switch` yoktu; Extreme `show version`'a yanıt verdiği için çıktı `_classify_device_type`'a ulaşmadan `cisco_ios` olarak etiketlenip interactive shell'e geçiliyordu. Banner'da her zaman "ExtremeXOS" geçmeyince `unknown` dönüyordu.

**Düzeltme (`dynamic_inventory_scan/service.py`):**
- `_DETECT_CMDS`'e `("show switch", "extreme_exos")` eklendi
- `_classify_device_type()` Extreme tespiti güçlendirildi: `System Type:`, `SysName:`, `Primary ver:` kalıpları eklendi

**Düzeltme (`inventory_collector/module.py`):**
- `_collect_extreme()`: Paramiko interactive shell ile `show switch` + `show version` çeker
- `_collect_ruijie()`: Paramiko interactive shell ile `show version` çeker
- `_paramiko_send_cmd()`: Banner temizleme + komut gönderme + çıktı okuma yardımcısı
- `_collect_single()`: `extreme/ruijie` tiplerini dedicated fonksiyonlara yönlendirir
- `_redetect_device_type()`: `device_type: unknown` cihazlar için SSH banner'a bakarak yeniden tespit

---

### 10.6 Yanlış `device_type` ile Envanter Alımı

**Sorun:** Cihaz `cisco_ios` olarak kaydedilmişken Ruijie çıktısı gelince `parse_cisco` çağrılıyor, model/brand bulunamıyordu.

**Düzeltme:** `_classify_output()` fonksiyonu eklendi. `_collect_ssh` içinde parser seçmeden önce çıktının içeriğine bakılır:

```python
real_type = _classify_output(version_out, device["device_type"])
parser = get_parser(real_type)  # device_type yerine real_type
```

---

### 10.7 Brand Kolonu Hatalı Gösterim

**Sorun:** Inventory tablosundaki Brand kolonu yalnızca `device_details.json`'dan okuyordu. Envanter al yapılmadan önce (veya eski Cisco kaydı varken) hatalı marka gösteriyordu.

**Düzeltme:** `web.py` Brand kolonu JavaScript'i: `device_details.json`'da `brand` yoksa `device_type`'tan türetir.

---

## 11. Yeni Cihaz Tipi Ekleme Rehberi

Yeni bir marka/platform eklemek için şu adımlar izlenmeli:

### Adım 1 — Parser Yaz

`app/modules/inventory_collector/parsers/yeni_marka.py` oluştur:

```python
import re

def parse_yeni_marka(version_output: str, extra_output: str = "") -> dict:
    data = {"brand": "Marka Adı"}
    
    # Model
    m = re.search(r"Model:\s+(\S+)", version_output)
    data["model"] = m.group(1) if m else None
    
    # Hostname
    m = re.search(r"hostname\s+(\S+)", version_output)
    data["hostname"] = m.group(1) if m else None
    
    # Serial
    m = re.search(r"Serial:\s+(\S+)", version_output)
    data["serial_no"] = m.group(1) if m else None
    
    # Version
    m = re.search(r"Version\s+([\d.]+)", version_output)
    data["software_version"] = m.group(1) if m else None
    
    # Uptime
    m = re.search(r"uptime\s+(.+)", version_output)
    data["uptime"] = m.group(1) if m else None
    
    return data
```

### Adım 2 — Parser'ı Kaydet

`parsers/__init__.py`'ye ekle:

```python
from .yeni_marka import parse_yeni_marka

# get_parser() içinde:
if "yeni_marka" in dt:
    return parse_yeni_marka
```

### Adım 3 — Cihaz Tipi Tespiti

`dynamic_inventory_scan/service.py` → `_classify_device_type`:

```python
if "yeni marka keyword" in out_lower:
    return "yeni_marka"
```

### Adım 4 — Komut Seçimi ve Dispatch

**Netmiko uyumluysa** → `module.py` → `_collect_ssh` içine ekle:
```python
elif "yeni_marka" in dt:
    cmd_version = "show version"
    cmd_extra   = ""
```

**Netmiko uyumlu değilse** → Paramiko tabanlı fonksiyon yaz:
```python
def _collect_yeni_marka(device, credentials, max_retry=3):
    # _collect_ruijie() veya _collect_extreme() örnek alın
    ...

# _collect_single() içine ekle:
if "yeni_marka" in dt:
    return _collect_yeni_marka(device, credentials, max_retry)
```

### Adım 5 — Tag ve Brand

`service.py` → `add_to_inventory` → tags bloğu:
```python
elif "yeni_marka" in dt_low:
    tags.append("yeni_marka")
```

`service.py` → `_build_device_name` → prefix_map:
```python
"yeni_marka": "YM",
```

`web.py` → brand tespiti (~1696. satır):
```python
"Yeni Marka" if "yeni_marka" in dt else
```

`web.py` → Brand kolonu JS (~3876. satır):
```javascript
if(dt.includes('yeni_marka')) return 'Yeni Marka';
```

`web.py` → Dropdown (~2951. satır):
```html
<option>yeni_marka</option>
```

### Adım 6 — _netmiko_type Haritası

`module.py` → `_NETMIKO_TYPE_MAP`:
```python
"yeni_marka":    "yeni_marka",  # Netmiko platform adı
"yeni_marka_v2": "yeni_marka",  # olası varyasyonlar
```

---

*Bu döküman projedeki son kod durumuyla günceldir. Yeni değişiklik yapıldıkça bu dosyayı güncelleyin.*
