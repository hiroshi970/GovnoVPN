# GovnoVPN

**VLESS-клиент** на основе [sing-box](https://github.com/SagerNet/sing-box) с современным GUI.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)

---

## Возможности

- Подключение по протоколу **VLESS** (TCP, WebSocket, gRPC, HTTP/2)
- Поддержка **TLS** и **Reality**
- Импорт серверов из `vless://` ссылок
- Управление несколькими профилями (добавление, редактирование, удаление)
- Автоматическая загрузка ядра **sing-box** с GitHub
- Адаптация к системной теме (тёмная / светлая)
- Сворачивание в системный трей
- Просмотр логов sing-box в реальном времени

## Структура проекта

```
govnovpn/
├── main.py              # Точка входа
├── requirements.txt     # Зависимости Python
├── README.md
└── app/
    ├── __init__.py      # Версия и имя приложения
    ├── gui.py           # Главное окно (CustomTkinter)
    ├── dialogs.py       # Диалоги: профиль, настройки, о программе, логи
    ├── profiles.py      # VLESS-профили, парсер URL, генератор конфига sing-box
    ├── singbox.py       # Менеджер процесса sing-box (скачивание, запуск, остановка)
    └── tray.py          # Иконка в системном трее (pystray)
```

## Установка

### 1. Клонируйте репозиторий

```bash
git clone <repo-url>
cd govnovpn
```

### 2. Создайте виртуальное окружение (рекомендуется)

```bash
python -m venv .venv
.venv\Scripts\activate     # Windows
# или
source .venv/bin/activate  # Linux / macOS
```

### 3. Установите зависимости

```bash
pip install -r requirements.txt
```

### 4. Запустите приложение

```bash
python main.py
```

> **Примечание:** при первом запуске нажмите кнопку **«Скачать»** для автоматической загрузки ядра sing-box.
> Для работы TUN-режима может потребоваться запуск от имени **администратора**.

## Использование

1. Запустите приложение → нажмите **«＋ Добавить»**
2. Вставьте `vless://...` ссылку и нажмите **«Импорт»**, либо заполните поля вручную
3. Нажмите **«Подключиться»**
4. Для переключения между серверами кликните по нужному в списке

## Настройки

- **Тема:** System / Dark / Light (адаптируется автоматически к ОС)
- **Цветовая схема:** blue / green / dark-blue

## Технологии

| Компонент | Технология |
|-----------|------------|
| GUI | [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) |
| VPN-ядро | [sing-box](https://github.com/SagerNet/sing-box) |
| Трей | [pystray](https://github.com/moses-palmer/pystray) |
| Тема ОС | [darkdetect](https://github.com/albertosottile/darkdetect) |

## Лицензия

MIT
