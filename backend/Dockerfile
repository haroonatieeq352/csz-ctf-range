FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Fresh, isolated DB per container instance
RUN python db.py

EXPOSE 5000
CMD ["gunicorn", "--workers=4", "--threads=4", "--worker-class=gthread", "--bind=0.0.0.0:5000", "--timeout=60", "--preload", "app:app"]
