# Firewall UI (Rust)

## Espanol

UI en terminal construida con ratatui para administrar nftables o iptables directamente.

### Requisitos

- Linux
- toolchain de Rust (cargo)
- nftables o iptables
- permisos de root

### Ejecutar

```bash
cd rust-ui
sudo cargo run
```

### Controles

- Flechas: arriba/abajo para reglas, izquierda/derecha para menu
- j-k: mover seleccion en el foco actual
- Enter: ejecutar accion
- t / Tab: cambiar foco (acciones/reglas)
- r: refrescar lista de reglas
- x: eliminar regla seleccionada (solo en foco reglas)
- b: alternar backend (nftables/iptables)
- d: alternar DRY-RUN
- l: alternar idioma (es/en/zh-CN)
- PgUp/PgDn: scroll en salida
- q: salir

### Notas

- Restaurar lista backups en `/var/backups/firewall-manager`.
- DRY-RUN imprime los comandos sin aplicarlos.

---

## English

Terminal UI built with ratatui to manage nftables or iptables directly.

### Requirements

- Linux
- Rust toolchain (cargo)
- nftables or iptables
- root privileges

### Run

```bash
cd rust-ui
sudo cargo run
```

### Controls

- Arrows: up/down for rules, left/right for menu
- j-k: move selection in current focus
- Enter: run action
- t / Tab: switch focus (actions/rules)
- r: refresh rules list
- x: delete selected rule (rules focus only)
- b: toggle backend (nftables/iptables)
- d: toggle DRY-RUN
- l: toggle language (es/en/zh-CN)
- PgUp/PgDn: scroll output
- q: quit

### Notes

- Restore lists backups in `/var/backups/firewall-manager`.
- DRY-RUN prints commands without applying them.

---

## 中文（简体）

基于 ratatui 的终端 UI，可直接管理 nftables 或 iptables。

### 依赖

- Linux
- Rust 工具链 (cargo)
- nftables 或 iptables
- root 权限

### 运行

```bash
cd rust-ui
sudo cargo run
```

### 操作

- 方向键: 上下用于规则，左右用于菜单
- j-k: 在当前焦点中移动选择
- Enter: 执行动作
- t / Tab: 切换焦点 (操作/规则)
- r: 刷新规则列表
- x: 删除选中的规则 (仅规则焦点)
- b: 切换后端 (nftables/iptables)
- d: 切换 DRY-RUN
- l: 切换语言 (es/en/zh-CN)
- PgUp/PgDn: 滚动输出
- q: 退出

### 说明

- 恢复会列出 `/var/backups/firewall-manager` 的备份。
- DRY-RUN 仅打印命令，不会执行。
