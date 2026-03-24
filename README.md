# Octopus — Network Automation

Flask tabanlı ağ otomasyon platformu. SSH ve REST API üzerinden ağ cihazlarından envanter toplar, tarama yapar, yedek alır.

## Kurulum

```bash
pip install -r requirements.txt
```

## Çalıştırma (Web arayüzü)

```bash
python -m app.web
```

## Çalıştırma (CLI)

```bash
python -m app.main
```

## Desteklenen Cihaz Tipleri

| device_type | Marka | Bağlantı |
|---|---|---|
| `cisco_ios` / `cisco_nxos` / `cisco_ap` | Cisco | Netmiko |
| `huawei` | Huawei | Netmiko |
| `h3c_comware` / `hp_comware` | H3C / HP | Netmiko |
| `dell_force10` | Dell | Netmiko |
| `extreme_exos` | Extreme Networks | Paramiko |
| `ruijie_os` | Ruijie Networks | Paramiko |
| `fortigate` | FortiGate | REST API |
| `fortianalyzer` / `fortimanager` / ... | Fortinet | Paramiko |
| `bigip` / `f5` | F5 BIG-IP | REST API |

## Proje Yapısı

```
octopus/
├── app/
│   ├── web.py                    # Flask API + SPA arayüzü
│   ├── main.py                   # CLI giriş noktası
│   ├── data/                     # JSON veri dosyaları
│   └── modules/
│       ├── dynamic_inventory_scan/   # Ağ tarama motoru
│       ├── inventory_collector/      # Envanter toplama
│       ├── network_backup/           # Config yedekleme
│       └── password_manager/         # Credential vault
├── requirements.txt
└── CODEBASE.md                   # Teknik dokümantasyon
```

Detaylı teknik dokümantasyon için [CODEBASE.md](CODEBASE.md) dosyasına bakın.
