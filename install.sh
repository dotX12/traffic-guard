#!/usr/bin/env bash

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Константы
REPO="dotX12/traffic-guard"
BINARY_NAME="traffic-guard"
INSTALL_DIR="/usr/local/bin"
LATEST_RELEASE_URL="https://github.com/${REPO}/releases/latest/download"
DEV_MODE=false

# Функция для вывода сообщений
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Проверка прав root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Необходимо запустить скрипт с правами root (sudo)"
        exit 1
    fi
}

# Определение архитектуры и ОС
detect_system() {
    local os=""
    local arch=""

    # Определение ОС
    case "$(uname -s)" in
        Linux*)
            os="linux"
            ;;
        *)
            log_error "Неподдерживаемая ОС: $(uname -s). Поддерживается только Linux"
            exit 1
            ;;
    esac

    # Определение архитектуры
    case "$(uname -m)" in
        x86_64|amd64)
            arch="amd64"
            ;;
        i386|i686)
            arch="386"
            ;;
        armv7l|armv6l)
            arch="arm"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        *)
            log_error "Неподдерживаемая архитектура: $(uname -m)"
            exit 1
            ;;
    esac

    echo "${os}-${arch}"
}

# Получение последнего релиза (включая pre-release если --dev)
get_latest_release_tag() {
    local api_url="https://api.github.com/repos/${REPO}/releases"

    if [ "$DEV_MODE" = true ]; then
        log_info "Режим DEV: поиск последнего релиза (включая pre-release)..."
        api_url="${api_url}?per_page=1"
    else
        api_url="${api_url}/latest"
    fi

    local tag=""
    if command -v curl &> /dev/null; then
        tag=$(curl -fsSL "${api_url}" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"\(.*\)"/\1/')
    elif command -v wget &> /dev/null; then
        tag=$(wget -qO- "${api_url}" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"\(.*\)"/\1/')
    else
        log_error "Не найден curl или wget. Установите один из них"
        exit 1
    fi

    if [ -z "$tag" ]; then
        log_error "Не удалось определить версию релиза"
        exit 1
    fi

    echo "$tag"
}

# Скачивание бинарника
download_binary() {
    local platform=$1
    local temp_file="/tmp/${BINARY_NAME}"
    local download_url=""

    if [ "$DEV_MODE" = true ]; then
        local tag=$(get_latest_release_tag)
        log_info "Найдена версия: ${tag}"
        download_url="https://github.com/${REPO}/releases/download/${tag}/${BINARY_NAME}-${platform}"
    else
        download_url="${LATEST_RELEASE_URL}/${BINARY_NAME}-${platform}"
    fi

    log_info "Скачивание ${BINARY_NAME} для ${platform}..."
    log_info "URL: ${download_url}"

    if command -v curl &> /dev/null; then
        if ! curl -fsSL "${download_url}" -o "${temp_file}"; then
            log_error "Ошибка при скачивании бинарника"
            exit 1
        fi
    elif command -v wget &> /dev/null; then
        if ! wget -q "${download_url}" -O "${temp_file}"; then
            log_error "Ошибка при скачивании бинарника"
            exit 1
        fi
    else
        log_error "Не найден curl или wget. Установите один из них"
        exit 1
    fi

    echo "${temp_file}"
}

# Установка бинарника
install_binary() {
    local temp_file=$1
    local install_path="${INSTALL_DIR}/${BINARY_NAME}"

    log_info "Установка в ${install_path}..."

    # Создаём директорию если не существует
    mkdir -p "${INSTALL_DIR}"

    # Копируем файл
    cp "${temp_file}" "${install_path}"

    # Выдаём права на выполнение
    chmod +x "${install_path}"

    # Удаляем временный файл
    rm -f "${temp_file}"

    log_info "Установка завершена успешно!"
}

# Проверка установки
verify_installation() {
    if command -v ${BINARY_NAME} &> /dev/null; then
        local version=$(${BINARY_NAME} --version 2>&1 | head -n1)
        log_info "✓ ${BINARY_NAME} успешно установлен"
        log_info "Версия: ${version}"
        log_info "Путь: $(which ${BINARY_NAME})"
        return 0
    else
        log_error "Установка не удалась"
        return 1
    fi
}

# Вывод информации об использовании
show_usage() {
    log_info ""
    log_info "⚠️  ВАЖНО: Обязательно укажите URL с списками подсетей через параметр -u"
    echo "" >&2
    log_info "Публичные списки доступны здесь:"
    echo "  https://github.com/shadow-netlab/traffic-guard-lists/tree/main" >&2
    log_info "Для получения полной справки:"
    echo "" >&2
    echo "  ${BINARY_NAME} --help" >&2
    echo "" >&2
}

# Вывод справки
show_help() {
    echo "Использование: $0 [OPTIONS]" >&2
    echo "" >&2
    echo "Опции:" >&2
    echo "  --dev       Установить последний релиз (включая pre-release)" >&2
    echo "  --help      Показать эту справку" >&2
    echo "" >&2
    exit 0
}

# Парсинг аргументов
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dev)
                DEV_MODE=true
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                log_error "Неизвестный параметр: $1"
                echo "Используйте --help для справки" >&2
                exit 1
                ;;
        esac
    done
}

# Главная функция
main() {
    # Парсинг аргументов
    parse_args "$@"

    log_info "=== Установка Traffic Guard ==="
    if [ "$DEV_MODE" = true ]; then
        log_warn "Режим DEV: будет установлена последняя версия (включая pre-release)"
    fi
    echo "" >&2

    # Проверка прав
    check_root

    # Определение системы
    local platform=$(detect_system)
    log_info "Определена система: ${platform}"

    # Скачивание
    local temp_file=$(download_binary "${platform}")

    # Установка
    install_binary "${temp_file}"

    # Проверка
    if verify_installation; then
        echo "" >&2
        show_usage
        exit 0
    else
        exit 1
    fi
}

# Запуск
main "$@"
