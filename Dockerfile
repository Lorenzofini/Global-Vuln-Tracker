# Usa un'immagine Python ufficiale e leggera come base
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Imposta la directory di lavoro all'interno del container
WORKDIR /app

# Copia prima il file dei requisiti per sfruttare la cache di Docker
# Se requirements.txt non cambia, Docker non re-installerà le dipendenze
COPY requirements.txt .

# Installa le dipendenze
RUN pip install --no-cache-dir -r requirements.txt

# Copia tutto il resto del codice dell'applicazione
# (il .dockerignore escluderà i file non necessari)
COPY config.yaml ./
COPY src/ ./src

# Comando che verrà eseguito all'avvio del container
# Usiamo lo stesso comando che usiamo localmente
CMD ["python", "-m", "src.main"]