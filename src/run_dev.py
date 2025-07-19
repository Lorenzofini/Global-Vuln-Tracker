# run_dev.py
import subprocess
import time
import os
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Comando per eseguire il nostro script principale
COMMAND = [sys.executable, "-m", "src.main"]
# File e cartelle da monitorare per le modifiche
PATHS_TO_WATCH = ['./src', './config.yaml', './.env']


class ChangeHandler(FileSystemEventHandler):
    """Gestisce gli eventi di modifica del filesystem."""

    def __init__(self):
        self.process = None
        self.start_process()

    def start_process(self):
        """Avvia o riavvia il processo dello script principale."""
        if self.process:
            print(">>> Rilevata modifica, riavvio lo script...")
            self.process.terminate()  # Termina il processo esistente
            self.process.wait()  # Attende che il processo sia terminato

        print(">>> Avvio dello script principale...")
        # Avviamo il comando in un nuovo processo
        self.process = subprocess.Popen(COMMAND)

    def on_any_event(self, event):
        """
        Questo metodo viene chiamato per qualsiasi evento (creazione, modifica, cancellazione).
        Filtriamo per evitare di riavviare per eventi non rilevanti.
        """
        # Ignora eventi su directory o su file temporanei/cache
        if event.is_directory or ".pyc" in event.src_path or "__pycache__" in event.src_path:
            return

        # Se un file viene modificato, riavviamo il processo
        if event.event_type == 'modified':
            self.start_process()


if __name__ == "__main__":
    # Assicura che i percorsi da monitorare esistano
    valid_paths = [path for path in PATHS_TO_WATCH if os.path.exists(path)]
    if not valid_paths:
        print("Errore: Nessun percorso valido da monitorare trovato.")
        exit(1)

    print(">>> Modalità sviluppo: avvio del monitoraggio delle modifiche...")
    print(f">>> Percorsi monitorati: {valid_paths}")

    event_handler = ChangeHandler()
    observer = Observer()

    for path in valid_paths:
        observer.schedule(event_handler, path, recursive=os.path.isdir(path))

    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(">>> Interruzione manuale, arresto del monitor e dello script.")
        observer.stop()
        if event_handler.process:
            event_handler.process.terminate()
            event_handler.process.wait()

    observer.join()
    print(">>> Uscita completata.")