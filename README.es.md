# NexHunt

**Plataforma de Automatización para Bug Bounty** by [Sentinel Security](https://sentinelsec.online)

> **Versión Beta** — en desarrollo activo. Pueden existir errores. Feedback bienvenido en [Issues](https://github.com/sentinelsec-org/nexhunt/issues).

NexHunt es una aplicación de escritorio para Linux que automatiza el flujo completo de bug bounty: enumeración de subdominios, sondeo de hosts activos, escaneo de vulnerabilidades, explotación y análisis con IA — todo desde una sola interfaz.

---

## Instalación rápida

```bash
curl -fsSL https://github.com/sentinelsec-org/nexhunt/releases/download/v1.1.0/nexhunt-1.1.0.tar.gz | tar xz && sudo bash install.sh
```

Luego ejecutá:

```bash
nexhunt
```

---

## Qué hace

| Fase | Herramientas |
|---|---|
| Recon | subfinder, amass, httpx, nmap, katana, gau, waybackurls, gowitness |
| Escaneo | nuclei, ffuf, nikto, gobuster, dirsearch |
| Explotación | sqlmap, dalfox, xsstrike, commix, paramspider, arjun |
| Proxy | captura, repeater, intruder (PRO) |
| Herramientas | CORS scanner, bypass 403, exposición cloud, secretos GitHub, interactsh |
| AI Copilot | análisis, sugerencias de ataque, generación de reportes — **PRO** |

---

## Gratis vs PRO

| Función | Gratis | PRO |
|---|:---:|:---:|
| Suite completa de recon | ✓ | ✓ |
| Scanner objetivo único | ✓ | ✓ |
| Exploit objetivo único | ✓ | ✓ |
| Proxy captura + repeater | ✓ | ✓ |
| Herramientas de seguridad | ✓ | ✓ |
| BD hallazgos, proyectos, metodología | ✓ | ✓ |
| AI Copilot (hosteado) | — | ✓ |
| Pipelines automatizados (XSS/SQLi/JS) | — | ✓ |
| Escaneo masivo (nuclei-bulk, recon completo) | — | ✓ |
| Proxy Intruder (cluster bomb/pitchfork) | — | ✓ |
| Suite de ataques JWT | — | ✓ |
| Suite de lógica de negocio | — | ✓ |

[Obtener PRO →](https://sentinelsec.online/pricing)

---

## Requisitos

- Linux (Kali, Debian, Ubuntu)
- Python 3.10+
- Node.js 18+
- Go 1.21+ (se instala automáticamente si no está)
- Conexión a internet para la instalación inicial de herramientas

El instalador se encarga del resto automáticamente.

---

## Activar licencia PRO

1. Comprá tu licencia en [sentinelsec.online/pricing](https://sentinelsec.online/pricing)
2. Abrí NexHunt → Ajustes → Licencia
3. Pegá tu clave de licencia y hacé click en Activar

La licencia PRO está atada a la máquina y se valida online. Período de gracia de hasta 7 días sin conexión.

---

## Actualizar

```bash
sudo bash install.sh --update
```

O usá la notificación de actualización dentro de la app (Ajustes → Actualizaciones).

---

## Problemas y feedback

[github.com/sentinelsec-org/nexhunt/issues](https://github.com/sentinelsec-org/nexhunt/issues)

---

**Sentinel Security** — [sentinelsec.online](https://sentinelsec.online)
