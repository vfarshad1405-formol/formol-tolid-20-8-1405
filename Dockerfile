FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
COPY templates ./templates
COPY seed ./seed
CMD ["sh", "-c", "exec gunicorn --workers 2 --threads 4 --timeout 90 --bind 0.0.0.0:${PORT:-8080} app:app"]
