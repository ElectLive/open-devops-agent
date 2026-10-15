FROM python:3.12-slim

WORKDIR /app
RUN useradd -m -u 1000 appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

USER appuser
ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "uvicorn app:app --host ${HOST:-0.0.0.0} --port ${PORT:-8080}"]
