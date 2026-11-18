# USB-Guard — агент прозрачного шифрования съёмных дисков для Windows

Агент-сервис Windows, который отслеживает подключение съёмных томов (USB flash,
SD и т.п.) и **в реальном времени шифрует их содержимое**, чтобы:

1. На доверенном ПК (с агентом) пользователь работает с файлами как обычно —
   шифрование/расшифровка прозрачны.
2. Если вынуть флешку и вставить в чужой ПК без агента — файлы лежат в
   зашифрованном виде и не читаются штатными средствами.
3. Если на чужом ПК на флешку закинули новый/изменённый файл — при возврате
   на доверенный ПК агент его подхватит и зашифрует.

## Как это устроено (архитектура)

```
 ┌──────────────────── Windows Service (usbguard-agent) ────────────────────┐
 │  VolumeWatcher      KeyProvider        CryptoEngine       Manifest       │
 │  (WMI + CM_Register │ (DPAPI /         (AES-256-GCM +     (JSON-реестр   │
 │   KernelNotificat.   TPM-sealed key,    блейз-конвейер)   файлов: id,    │
 │   + USN-журнал      кэш в ProgramData)                   путь, sha256,   │
 │                                                         статус))         │
 │                └────────────── SyncOrchestrator ──────────────┘          │
 │   сканирует том → новые/изменённые файлы → очередь → .enc на носителе    │
 └───────────────────────────────────────────────────────────────────────────┘
```

### Два принципиально разных подхода

| Подход | Плюсы | Минусы |
|---|---|---|
| **A. Minifilter-драйвер** (как EFS / BitLocker To Go) | Идеально прозрачно, нулевая задержка | Ядерный драйвер KMDF, EV-сертификат + attestation-подпись Microsoft, месяцы сертификации |
| **B. Агент + синхронизатор** (этот проект) | Полностью usermode, ставится за минуты | Окно в ~1–3 сек между появлением файла и шифрованием; «прозрачность» даёт CLI `usbguard` |

Реализован **подход B** (production-подобный каркас). План миграции на
minifilter — `docs/DRIVER_PLAN.md`.

### Модель хранения на флешке

```
E:\
 ├─ .usbguard\
 │   ├─ manifest.json        # исходный путь → id, sha256, mtime, размер
 │   └─ manifest.json.bak
 ├─ Документы\
 │   ├─ отчёт.xlsx.enc       # AES-256-GCM, ключ = HKDF(master, file_id)
 │   └─ презентация.pptx.enc
 └─ фото.jpg.enc
```

* Формат `.enc`: магический `USBG`, версия, file_id, nonce(12), tag, chunks.
* Master key — в **DPAPI (CurrentUser+LocalMachine)**, опционально seal в
  **TPM 2.0** (`docs/KEYS.md`). Без агента и ключа содержимое недоступно.
* Файлы без `.enc`, найденные при сканировании (принесли с чужого ПК),
  шифруются и заменяются оригинал-копией — это «обратная сторона» задачи.

## Быстрый старт (Windows 10/11, .NET 8 SDK)

```powershell
dotnet publish src/UsbGuard.Agent -c Release -r win-x64 --self-contained -o agent
dotnet publish src/UsbGuard.Cli   -c Release -r win-x64 --self-contained -o cli

.\install.ps1        # регистрация сервиса (админ. PowerShell)

usbguard list                        # файлы текущего съёмного тома
usbguard cat  E:\Документы\отчёт.xlsx.enc > отчёт.xlsx
usbguard extract E:\фото.jpg.enc -o $env:USERPROFILE\Desktop
usbguard sync                          # ручная принудительная синхронизация
usbguard status
```

## Структура репозитория

```
src/UsbGuard.Core/     # криптоядро: формат .enc, манифест, ключи — кроссплатформенно
src/UsbGuard.Agent/    # Windows-сервис: наблюдатель томов, планировщик синхронизации
src/UsbGuard.Cli/      # команда usbguard
tests/UsbGuard.Core.Tests/
docs/                  # KEYS.md, THREAT_MODEL.md, DRIVER_PLAN.md
install.ps1 / uninstall.ps1
```

## Важные ограничения (честно)

* Окно незащищённости ~1–3 секунды (polling + USN-журнал). Нулевое окно —
  только minifilter (`docs/DRIVER_PLAN.md`).
* Агент защищает от чтения без ключа, но не от форматирования носителя.
* DPAPI-CURRENTUSER привязывает ключ к учётке: потеря пароля = потеря ключа.
  Предусмотрен escrow: `usbguard key export-backup` (см. `docs/KEYS.md`).
* Модель угроз — `docs/THREAT_MODEL.md`.

## Лицензия

MIT
