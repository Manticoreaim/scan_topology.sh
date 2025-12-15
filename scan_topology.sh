#!/bin/bash

SCRIPT_NAME="scan_topology.sh"
PY_SCRIPT="nmap_topology.py"
XML_FILE="network.xml"
PNG_OUTPUT="network_topology.png"

show_help() {
    cat <<EOF
Использование: $SCRIPT_NAME <CIDR-подсеть>

Пример:
  ./$SCRIPT_NAME 192.168.1.0/24

Описание:
  Сканирует указанную подсеть с помощью nmap, строит граф топологии
  и сохраняет его как '$PNG_OUTPUT'.

Зависимости:
  - nmap
  - python3
  - Python-пакеты: networkx, matplotlib, lxml
    (установка: pip3 install networkx matplotlib lxml)

Файлы:
  - Вход: не требуется (сканирует сеть)
  - Выход: $XML_FILE (результат nmap), $PNG_OUTPUT (граф)
  - Временный Python-скрипт: $PY_SCRIPT (удаляется после работы)

EOF
}

# Проверка аргументов
if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]] || [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

if [[ $# -ne 1 ]]; then
    echo "Ошибка: ожидается ровно один аргумент (CIDR-подсеть)." >&2
    echo "Смотрите: ./$SCRIPT_NAME -h" >&2
    exit 1
fi

CIDR="$1"

# Валидация CIDR (простая)
if ! [[ "$CIDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
    echo "Ошибка: '$CIDR' не похоже на CIDR-подсеть (например, 192.168.1.0/24)." >&2
    exit 1
fi

echo "[+] Сканирую сеть: $CIDR"

# Запуск nmap
if ! sudo nmap -sn "$CIDR" -oX "$XML_FILE"; then
    echo "Ошибка: nmap завершился с ошибкой." >&2
    exit 1
fi

echo "[+] Скан завершён. Результат сохранён в $XML_FILE"

# Создаём Python-скрипт
cat > "$PY_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import networkx as nx
import matplotlib.pyplot as plt
import sys

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts = []
    for host in root.findall('host'):
        ip = None
        mac = None
        hostname = None
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is not None:
            ip = addr_elem.get('addr')
        mac_elem = host.find("address[@addrtype='mac']")
        if mac_elem is not None:
            mac = mac_elem.get('addr')
        hostnames = host.find('hostnames')
        if hostnames is not None:
            hn = hostnames.find('hostname')
            if hn is not None:
                hostname = hn.get('name')
        if ip:
            hosts.append({'ip': ip, 'mac': mac, 'hostname': hostname})
    return hosts

def build_and_draw_graph(hosts, output_file='network_topology.png'):
    G = nx.Graph()
    network_node = "Local Network"
    G.add_node(network_node, color='lightblue', size=2000)
    for h in hosts:
        label = h['ip']
        if h['hostname']:
            label += f"\n{h['hostname']}"
        elif h['mac']:
            label += f"\n{h['mac']}"
        G.add_node(label, color='lightgreen')
        G.add_edge(network_node, label)
    plt.figure(figsize=(14, 10))
    pos = nx.spring_layout(G, seed=42)
    colors = [G.nodes[n].get('color', 'gray') for n in G.nodes()]
    sizes = [G.nodes[n].get('size', 800) for n in G.nodes()]
    nx.draw(G, pos, with_labels=True, node_color=colors, node_size=sizes,
            font_size=9, font_weight='bold', edge_color='gray', alpha=0.9)
    plt.title("Network Topology (from nmap -sn)", fontsize=16)
    plt.tight_layout()
    plt.savefig(output_file, dpi=150)
    print(f"✅ Топология сохранена в: {output_file}")
    plt.show()

def main():
    hosts = parse_nmap_xml('network.xml')
    print(f"Найдено {len(hosts)} хостов.")
    build_and_draw_graph(hosts)

if __name__ == "__main__":
    main()
PYEOF

echo "[+] Запускаю Python-скрипт для построения графа..."

# Запуск Python-скрипта
if ! python3 "$PY_SCRIPT"; then
    echo "Ошибка: не удалось выполнить Python-скрипт." >&2
    echo "Убедитесь, что установлены зависимости: pip3 install networkx matplotlib lxml" >&2
    rm -f "$PY_SCRIPT"
    exit 1
fi

# Удаляем временный Python-скрипт
rm -f "$PY_SCRIPT"
echo "[+] Временный скрипт удалён."

echo "[+] Готово! Граф сохранён в $PNG_OUTPUT"
