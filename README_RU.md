# ⚡ Pingtop

[English version](README.md)

**Pingtop** — легковесный кроссплатформенный (Linux & macOS) интерактивный TUI-монитор задержки, маршрутов (MTR) и качества сети (`ICMP ping`, `TCP ping`, `jitter`, `packet loss`, перцентили $p_{50}$–$p_{99}$), написанный на современном **C++20** без внешних зависимостей (**Zero External Dependencies**).

---

## Возможности

- **Движок ICMP, ICMPv6, Неблокирующий TCP и DNS Benchmark**:
  - Сборка и разбор `ICMP Echo Request` / `Echo Reply` (RFC 792) и **IPv6 `ICMPv6` (RFC 4443)** напрямую через сокеты.
  - Поддержка **TCP SYN Ping** (`host:port`, например `1.1.1.1:443`, `github.com:443`) для серверов, блокирующих ICMP файрволом.
  - Поддержка **DNS Benchmark по UDP порту 53** (`dns://1.1.1.1`, `dns://8.8.8.8`, DNS роутера) через пакеты RFC 1035 для замера реальной скорости резолвинга доменов.
- **Работа без root**: использование датаграммных сокетов (`SOCK_DGRAM` / `IPPROTO_ICMP` / `IPPROTO_ICMPV6`) на macOS и современных Linux с прозрачным fallback на `SOCK_RAW`.
- **GeoIP и ASN (Провайдер и страна)**: автоматическое определение страны, номера автономной системы (`ASN`) и оператора связи (через DNS TXT `asn.cymru.com` и встроенную таблицу) для каждого хоста и каждого промежуточного узла в MTR.
- **Тест MTU / Path MTU Discovery (клавиша `m`)**: автоопределение MTU маршрута/туннеля (`1500B` Ethernet/Wi-Fi, `1280B` Tailscale/WireGuard) и активный тест **Path MTU с флагом Don't Fragment (DF)** бинарным поиском (`576..1500B`).
- **Встроенный живой MTR / Traceroute (клавиша `t`)**: пошаговая трассировка маршрута с отображением GeoIP/ASN, RTT, потерь и спарклайном на каждом промежуточном хопе.
- **Экран 2D-графика, перцентилей и гистограммы (клавиша `Enter`)**:
  - Расчет перцентилей задержки **$p_{50}$ (медиана), $p_{90}$, $p_{95}$, $p_{99}$**, стандартного отклонения ($\sigma$) и джиттера **RFC 3550**;
  - Многострочный 2D-график истории RTT и гистограмма распределения задержек по диапазонам.
- **Автоопределение топологии и группировка по категориям (`g` и `d`)**:
  - Автоматический поиск роутера (`Router / Gateway`), локальных устройств из таблицы **ARP** (свитчей, ТВ, ПК с обратным DNS) и туннелей **VPN / Tailscale** (`utun`, `wg`);
  - Автоматическое обнаружение **активных SSH-сессий** (Termius, системный `ssh`, VS Code) и серверов в Tailscale с параллельным замером ICMP-пинга и прямой TCP-задержки до 22 порта;
  - Визуальная группировка в секции `[LOCAL GATEWAY & LAN]`, `[VPN & TAILSCALE]` и `[INTERNET & WAN]`.
- **Живой поиск и фильтрация (клавиша `/`)**: мгновенный фильтр строк таблицы по имени, IP или протоколу (`ICMP` / `TCP`).
- **Конфигурационный файл (`~/.config/pingtop/hosts.conf`)**: автоматическое создание и загрузка пользовательского списка серверов и секций при старте.

---

## Структура проекта

```text
pingtop/
├── CMakeLists.txt
├── LICENSE
├── README.md
├── README_RU.md
├── .gitignore
├── include/
│   ├── icmp_socket.hpp
│   ├── network_monitor.hpp
│   ├── ring_buffer.hpp
│   └── tui_renderer.hpp
└── src/
    ├── icmp_socket.cpp
    ├── main.cpp
    ├── network_monitor.cpp
    └── tui_renderer.cpp
```

---

## Сборка и запуск

### macOS (Clang / AppleClang)

```bash
# Сборка через CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# Или напрямую компилятором
clang++ -std=c++20 -O2 -Wall -Wextra -Wpedantic -Iinclude \
    src/main.cpp src/icmp_socket.cpp src/network_monitor.cpp src/tui_renderer.cpp \
    -o pingtop

# Сделать команду 'pingtop' доступной из любой папки терминала
ln -sf "$(pwd)/pingtop" /opt/homebrew/bin/pingtop

# Запуск
pingtop
```

### Linux (GCC 10+ / Clang 12+)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Если непривилегированный пинг ограничен политиками ядра:
```bash
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
# или
sudo setcap cap_net_raw+ep ./build/pingtop
```

---

## Примеры использования

```bash
# Автопоиск LAN, VPN/Tailscale и загрузка ~/.config/pingtop/hosts.conf
pingtop

# Мониторинг ICMP и TCP (host:port) целей
pingtop 1.1.1.1 github.com:443 8.8.8.8:53

# Именованные метки и интервал 500 мс
pingtop -i 500 Router=192.168.1.1 Web=google.com:443
```

---

## Горячие клавиши

| Клавиша | Действие |
| :--- | :--- |
| `Enter` / `v` | Открыть **2D-график, перцентили ($p_{50}$–$p_{99}$), Geo/ASN и гистограмму** для выбранного хоста |
| `t` | Открыть живой **MTR / Traceroute по хопам** с отображением GeoIP/ASN каждого узла |
| `m` | Запустить активный тест **Path MTU Discovery (Don't Fragment бинарный поиск)** для выбранного хоста |
| `/` | Живой **поиск и фильтрация** хостов по имени, IP, ASN или протоколу |
| `g` | Включить / выключить **группировку по категориям** (`LAN` / `VPN` / `WAN`) |
| `d` | Повторное сканирование локальных устройств (**ARP**) и узлов **VPN / Tailscale** |
| `s` | Смена колонки сортировки (`Default` → `Last RTT` → `Avg RTT` → `Jitter` → `Loss%`) |
| `r` | Сброс статистики и графиков |
| `p` / `Space` | Пауза / возобновление опроса |
| `+` / `-` | Изменение интервала опроса (±100 мс) |
| `↑` / `↓` (`k` / `j`) | Выбор хоста в таблице |
| `b` / `Esc` | Возврат в основную таблицу / сброс поискового фильтра |
| `q` | Выход с печатью итоговой таблицы |
