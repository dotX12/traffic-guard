# TrafficGuard

Утилита для блокировки сканеров портов через iptables и ipset с поддержкой логирования и агрегации статистики.

## Содержание

- [О проекте](#о-проекте)
  - [Зачем это нужно?](#зачем-это-нужно)
  - [Способы использования](#способы-использования)
  - [Правовой статус и легальность](#правовой-статус-и-легальность)
- [Быстрый старт](#быстрый-старт)
- [Установка](#установка)
  - [Автоматическая установка](#автоматическая-установка)
  - [Ручная установка](#ручная-установка)
- [Возможности](#возможности)
- [Использование](#использование)
  - [Публичные списки](#публичные-списки)
  - [Примеры использования](#примеры-использования)
  - [Опции](#опции)
- [Удаление (uninstall)](#удаление-uninstall)
- [Логирование](#логирование)
  - [Конфигурация](#конфигурация)
  - [Файлы логов](#файлы-логов)
  - [Формат агрегированного CSV](#формат-агрегированного-csv)
  - [Лимиты логирования](#лимиты-логирования)
  - [Просмотр логов](#просмотр-логов)
- [Что создается в системе](#что-создается-в-системе)
- [Лицензия](#лицензия)

---

## О проекте

### Зачем это нужно?

**TrafficGuard** - это инструмент сетевой безопасности, который защищает ваш сервер от автоматизированного сканирования портов и несанкционированных попыток подключения.

**Основные проблемы, которые решает:**

1. **Массовое сканирование портов** - различные сканеры постоянно проверяют открытые порты на серверах в интернете, создавая ненужную нагрузку и потенциальные риски безопасности

2. **Нагрузка на сервисы** - каждая попытка подключения потребляет ресурсы сервера (CPU, память, сетевой трафик). При массовом сканировании это может замедлить работу легитимных сервисов

3. **Риски безопасности** - сканирование часто является первым этапом атаки. Злоумышленники ищут уязвимые сервисы и открытые порты для эксплуатации

4. **Засорение логов** - попытки подключения от сканеров заполняют системные логи, затрудняя анализ реальных проблем

5. **Неэффективное использование ресурсов** - ваши сервисы (веб-сервер, SSH, база данных) тратят время на обработку запросов от сканеров вместо обслуживания реальных пользователей

**TrafficGuard блокирует весь трафик с известных IP-адресов сканеров на уровне сетевого фильтра (iptables), до того как пакеты достигнут ваших сервисов.**

### Способы использования

#### 1. Базовая защита сервера

Защитите ваш VPS/сервер от массовых сканеров:

```bash
sudo traffic-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list
```

**Результат:** Весь трафик с IP-адресов известных сканеров будет отброшен на уровне firewall, не достигая ваших сервисов.

#### 2. Защита с мониторингом

Включите логирование, чтобы видеть статистику блокировок:

```bash
sudo traffic-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  --enable-logging
```

**Результат:** Дополнительно получаете CSV-файл с агрегированной статистикой: какие IP пытались подключиться, из каких сетей (ASN, NETNAME), сколько раз.

#### 3. Комплексная защита

Используйте несколько списков блокировки для максимальной защиты:

```bash
sudo traffic-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  --enable-logging
```

**Результат:** Блокируются как публичные сканеры, так и специфические подсети государственных организаций, проводящих массовое сканирование.

#### 4. Собственные списки блокировки

Создайте собственный список IP/подсетей для блокировки:

```bash
# Создайте файл с подсетями (по одной на строку)
cat > /tmp/my-blocklist.txt <<EOF
192.168.1.0/24
10.0.0.0/8
2001:db8::/32
EOF

# Разместите файл на веб-сервере или используйте file://
sudo traffic-guard full -u file:///tmp/my-blocklist.txt
```

### Правовой статус и легальность

**⚖️ ВАЖНОЕ ЮРИДИЧЕСКОЕ РАЗЪЯСНЕНИЕ**

#### Что это такое юридически?

**TrafficGuard является легальным инструментом сетевой безопасности класса "firewall" (межсетевой экран).**

#### Правовая квалификация

1. **Это обычный firewall** - TrafficGuard использует стандартные механизмы Linux (iptables/ipset), которые являются штатными компонентами операционной системы для управления сетевым трафиком

2. **Законное право на защиту** - владелец сервера/инфраструктуры имеет полное законное право контролировать входящие соединения и блокировать нежелательный трафик

3. **Аналог антивируса** - так же как антивирус блокирует вредоносные программы, TrafficGuard блокирует подозрительный сетевой трафик

#### Что делает утилита с точки зрения закона?

- ✅ **Блокирует входящие подключения** к вашему серверу с определенных IP-адресов
- ✅ **Не осуществляет атаки** на другие системы
- ✅ **Не перехватывает чужой трафик**
- ✅ **Не нарушает работу других систем**
- ✅ **Защищает только вашу инфраструктуру**

Это аналогично тому, как вы закрываете дверь в свой дом или устанавливаете сигнализацию.

#### Правовые основания (Российская Федерация)

**Статья 16 Федерального закона от 27.07.2006 N 149-ФЗ "Об информации":**

> Владелец информационной системы вправе устанавливать ограничения доступа к информации

**Статья 209 ГК РФ (право собственности):**

> Собственник вправе по своему усмотрению совершать в отношении принадлежащего ему имущества любые действия

**Федеральный закон от 27.07.2006 N 152-ФЗ "О персональных данных":**

> Оператор обязан принимать необходимые меры по защите персональных данных

#### Может ли быть привлечение к ответственности?

**НЕТ**, если вы:

- Используете утилиту для защиты **собственной инфраструктуры**
- Блокируете только **входящий трафик на свой сервер**
- Не используете для атак или нарушения работы других систем

**TrafficGuard НЕ является:**

- ❌ Средством взлома
- ❌ Инструментом DDoS-атак
- ❌ ПО для незаконного доступа к информации
- ❌ Средством обхода защиты

**Вы имеете право решать, кто может подключаться к вашему серверу.**

#### Для государственных органов

Если представители правоохранительных органов интересуются этой утилитой:

**TrafficGuard - это стандартный межсетевой экран (firewall), который:**

1. Использует только легальные системные компоненты Linux (iptables, ipset)
2. Блокирует входящие соединения к защищаемому серверу
3. Не осуществляет никаких активных действий в сторону других систем
4. Является инструментом защиты информации, аналогичным коммерческим решениям (Cisco ASA, pfSense, и т.д.)
5. Реализует требования по защите информации согласно 152-ФЗ и другим нормативным актам

**Использование данной утилиты является законным осуществлением права на защиту собственной информационной инфраструктуры.**

#### Рекомендации

- ✅ Используйте для защиты собственных серверов
- ✅ Документируйте настройки безопасности
- ✅ Храните логи в соответствии с требованиями законодательства
- ❌ Не используйте для блокировки доступа к чужим ресурсам
- ❌ Не используйте в составе инфраструктуры для незаконной деятельности

---

## Быстрый старт

Установка и запуск за 30 секунд:

```bash
# 1. Установка
curl -fsSL https://raw.githubusercontent.com/dotX12/traffic-guard/master/install.sh | sudo bash

# 2. Запуск с базовой защитой
sudo traffic-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list

# 3. (Опционально) Проверка статистики блокировок через 10 минут
tail -f /var/log/iptables-scanners-aggregate.csv
```

## Установка

### Автоматическая установка

Скачайте и запустите установочный скрипт:

```bash
curl -fsSL https://raw.githubusercontent.com/dotX12/traffic-guard/master/install.sh | sudo bash
```

или

```bash
wget -qO- https://raw.githubusercontent.com/dotX12/traffic-guard/master/install.sh | sudo bash
```

Скрипт автоматически:

- Определит архитектуру системы (amd64, 386, arm, arm64)
- Скачает последний релиз для вашей системы
- Установит бинарник в `/usr/local/bin`
- Выдаст права на выполнение

### Ручная установка

1. Скачайте нужный бинарник из [последнего релиза](https://github.com/dotX12/traffic-guard/releases/latest):

   - `traffic-guard-linux-amd64` - для 64-битных систем
   - `traffic-guard-linux-386` - для 32-битных систем
   - `traffic-guard-linux-arm` - для ARM
   - `traffic-guard-linux-arm64` - для ARM64

2. Установите:

```bash
sudo mv traffic-guard-linux-* /usr/local/bin/traffic-guard
sudo chmod +x /usr/local/bin/traffic-guard
```

## Возможности

- 📥 Скачивание списков подсетей сканеров из внешних источников
- 🛡️ Автоматическая настройка iptables/ip6tables правил
- 📊 Управление ipset наборами для IPv4 и IPv6
- 📝 Легковесное логирование с агрегацией (опционально)
- 🔄 Автоматическое сохранение правил для применения после перезагрузки

## Использование

### ⚠️ Важно

**Обязательно** необходимо передать один или несколько URL с списками подсетей через параметр `-u`:

```bash
sudo traffic-guard full -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list
```

Можно указать несколько источников:

```bash
sudo traffic-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list \
  --enable-logging
```

### Публичные списки

Готовые списки подсетей сканеров доступны в репозитории:
**[shadow-netlab/traffic-guard-lists](https://github.com/shadow-netlab/traffic-guard-lists/tree/main)**

Доступные списки:

- `public/antiscanner.list` - список от **[sngvy/AntiScanner](https://github.com/sngvy/AntiScanner)**
- `public/government_networks.list` - подсети различных сканеров государственных организаций

### Примеры использования

Базовая блокировка без логирования:

```bash
sudo traffic-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list
```

С включенным логированием:

```bash
sudo traffic-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list \
  --enable-logging
```

### Опции

- **`-u, --urls`** (обязательно) - URL для скачивания подсетей. Можно указать несколько раз
- `-l, --enable-logging` - включить логирование заблокированных подключений
- `--log-level` - уровень логирования (debug, info, warn, error). По умолчанию: info

## Удаление (uninstall)

Команда `uninstall` пошагово удаляет изменения, внесенные TrafficGuard:

- удаляет правила и цепочку `SCANNERS-BLOCK` из `iptables/ip6tables`
- удаляет managed-блоки из `/etc/ufw/before.rules` и `/etc/ufw/before6.rules`
- удаляет наборы `ipset` (`SCANNERS-BLOCK-V4`, `SCANNERS-BLOCK-V6`) и `/etc/ipset.conf`
- останавливает и отключает сервисы `antiscan-*`, удаляет созданные unit-файлы
- удаляет конфиги rsyslog/logrotate и скрипт агрегации

Что **не** делает uninstall по умолчанию:

- не удаляет системные пакеты (`iptables`, `ipset`, `netfilter-persistent`)
- не удаляет логи в `/var/log` (для этого используйте `--remove-logs`)
- не изменяет состояние UFW (active/inactive), кроме reload при очистке managed-блоков
- не откатывает таблицы маршрутизации, так как TrafficGuard их не модифицирует

Примеры:

```bash
# Интерактивное удаление
sudo traffic-guard uninstall

# Удаление без подтверждения
sudo traffic-guard uninstall --yes

# Удаление с очисткой логов
sudo traffic-guard uninstall --yes --remove-logs
```

### Интеграционный тест full -> uninstall

Для проверки сценария на чистой Linux VM есть отдельный интеграционный скрипт:

```bash
sudo ./tests/integration/full_uninstall_flow.sh
```

Что делает сценарий:

- запускает `full` с реальными публичными списками:
  - `https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list`
  - `https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list`
- проверяет создание `ipset`, `iptables/ip6tables` цепочек и служебных файлов
- если на хосте доступен `rsyslog`, дополнительно проверяет артефакты логирования
- запускает `uninstall --yes` и проверяет, что артефакты удалены
- повторяет цикл и проверяет `uninstall --yes --remove-logs`

Требования:

- Linux
- root права
- установленный `systemd`
- доступ в интернет к `raw.githubusercontent.com`
- запуск только на изолированной тестовой VM (не production)
- наличие go, iptables, ip6tables, iptables-save, ip6tables-save, ipset

Проверялось на debian 13.

## Логирование

### Конфигурация

При включении логирования (`--enable-logging`) создаются:

1. **`/etc/rsyslog.d/10-iptables-scanners.conf`** - конфигурация rsyslog
2. **`/etc/logrotate.d/iptables-scanners`** - ротация логов (каждый час, хранится 2 часа)
3. **`/usr/local/bin/antiscan-aggregate-logs.sh`** - скрипт агрегации
4. **`/etc/systemd/system/antiscan-aggregate.service`** - systemd service
5. **`/etc/systemd/system/antiscan-aggregate.timer`** - systemd timer (каждые 10 секунд)

### Файлы логов

- **`/var/log/iptables-scanners-ipv4.log`** - сырые логи IPv4 (обрабатываются каждые 30 сек)
- **`/var/log/iptables-scanners-ipv6.log`** - сырые логи IPv6 (обрабатываются каждые 30 сек)
- **`/var/log/iptables-scanners-aggregate.csv`** - агрегированная статистика в CSV формате

### Формат агрегированного CSV

Файл `/var/log/iptables-scanners-aggregate.csv` содержит статистику с автоматическим whois lookup:

```csv
IP_TYPE|IP_ADDRESS|ASN|NETNAME|COUNT|LAST_SEEN
v4|85.142.100.138|AS49505|JSCCYBEROK-NET|237|2026-01-25T17:08:01.123456+03:00
v6|2001:db8::1|AS12345|EXAMPLE-NET|12|2026-01-25T17:08:05.987654+03:00
```

**Поля:**

- `IP_TYPE` - тип IP (v4/v6)
- `IP_ADDRESS` - IP адрес сканера
- `ASN` - номер автономной системы (из whois)
- `NETNAME` - имя сети (из whois)
- `COUNT` - количество попыток подключения
- `LAST_SEEN` - время последней попытки

**Особенности:**

- Whois lookup с кэшированием (не повторяется для одного IP)
- Таймаут lookup: 3 секунды
- CSV отсортирован по COUNT (самые активные сверху)

### Лимиты логирования

- Максимум **10 записей в минуту** на каждый IP (чтобы не засорять логи)
- Топ-50 активных IP в каждом интервале агрегации

### Просмотр логов

```bash
# Последние агрегированные данные
tail -f /var/log/iptables-scanners-aggregate.csv

# Статус systemd timer
systemctl status antiscan-aggregate.timer

# Логи агрегатора
journalctl -u antiscan-aggregate.service -f
```

## Что создается в системе

### iptables

- **Цепочка**: `SCANNERS-BLOCK`
- **Правила**:
  - IPv4: `INPUT -j SCANNERS-BLOCK`
  - IPv6: `INPUT -j SCANNERS-BLOCK`
  - `SCANNERS-BLOCK -m set --match-set SCANNERS-BLOCK-V4 src -j DROP` (IPv4)
  - `SCANNERS-BLOCK -m set --match-set SCANNERS-BLOCK-V6 src -j DROP` (IPv6)

С логированием добавляются дополнительные правила с rate-limit.

### ipset

- **Наборы**:
  - `SCANNERS-BLOCK-V4` - hash:net для IPv4
  - `SCANNERS-BLOCK-V6` - hash:net для IPv6
- **Конфигурация**: `/etc/ipset.conf`

### Автозагрузка

Правила автоматически сохраняются:

- **Debian/Ubuntu**: `/etc/iptables/rules.v4`, `/etc/iptables/rules.v6`
- **RedHat/CentOS**: через `service iptables save`

## Лицензия

MIT
