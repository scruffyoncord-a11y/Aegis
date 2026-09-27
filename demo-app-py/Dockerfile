# Aegis FastAPI demo target -- built and run only inside Aegis's own
# disposable sandbox, never deployed. Binds port 8000 (uvicorn default),
# which is the port Aegis's probe expects for a FastAPI app.

FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
