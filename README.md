# 🔐 Bóveda Personal Linux

Bóveda de archivos cifrada para Linux, desarrollada en Python.

Utiliza **Argon2id** para derivar la clave desde la contraseña y **AES-256-GCM** para cifrar y autenticar los datos.

## ✨ Características

- 🔒 Cifrado AES-256-GCM
- 🔑 Derivación de claves con Argon2id
- 🧂 Salt aleatorio por bóveda
- 🎲 DEK aleatoria protegida por la contraseña
- 🛡️ Protección contra modificaciones del archivo
- 🔐 Bloqueo para evitar accesos simultáneos
- 💾 Escrituras atómicas para reducir el riesgo de corrupción
- 🐧 Diseñado para sistemas Linux

## 📋 Requisitos

- Linux
- Python 3.10 o superior
- `argon2-cffi`
- `cryptography`

## 📦 Instalación

Clonar el repositorio:

```bash
git clone https://github.com/sarco-rdf/Boveda-personal-linux.git
cd Boveda-personal-linux
```

Instalar las dependencias:

```bash
python3 -m pip install argon2-cffi cryptography
```

## 🚀 Uso

### Crear una bóveda

```bash
python3 boveda.py create
```

Se solicitará una contraseña y se creará:

`~/.boveda/boveda.svlt`

### Abrir la bóveda

```bash
python3 boveda.py open
```

### Verificar la bóveda

```bash
python3 boveda.py verify
```

Una bóveda válida mostrará:

```text
BOVEDA OK
```

## 🔑 Seguridad

La contraseña nunca se almacena directamente.

La bóveda utiliza **Argon2id** para derivar la clave y **AES-256-GCM** para cifrar y autenticar los datos.
