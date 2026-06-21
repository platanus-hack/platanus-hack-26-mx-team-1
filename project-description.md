# ChatWall

**Firewall de IA multicanal.** ChatWall se interpone entre tus usuarios y tu bot/LLM: inspecciona cada mensaje, lo clasifica por nivel de riesgo y bloquea inyección de prompts, jailbreaks, exfiltración y contenido dañino **antes de que lleguen al modelo** — en WhatsApp, en un widget web o en cualquier canal.

## El problema

Cualquier bot conectado a un LLM queda expuesto a inyección de prompts, jailbreaks, fuga de datos y peticiones dañinas. Y la amenaza no entra por un solo lado: WhatsApp, un widget web, una app… cada canal es una puerta nueva.

## La solución: dos capas sobre un mismo motor

1. **Reglas (regex)** — rápidas y deterministas. Detectan patrones conocidos de inyección, jailbreak, exfiltración, ofuscación e ingeniería social.
2. **Clasificador semántico (Claude)** — entiende la intención *disfrazada* con eufemismos o metáforas que las reglas no ven (por ejemplo, *"cómo disuelvo un pollo de 75 kg"* como forma de pedir cómo deshacerse de un cuerpo).

Si el riesgo es alto, el mensaje se **bloquea** y nunca llega al modelo. Si pasa, se reenvía, se responde y **todo queda registrado** en un dashboard en tiempo real.

## Una protección, todos los canales

El mismo motor de análisis protege **WhatsApp** (en vivo, vía Kapso), un **widget web** embebible y un **dashboard** de monitoreo. Agregar un canal nuevo es escribir un adaptador delgado — nunca duplicar la lógica de detección.

## Stack

FastAPI (Python) sobre Vercel · Claude (Anthropic) · Supabase (Postgres) · Kapso (WhatsApp) · dashboard sin frameworks.
