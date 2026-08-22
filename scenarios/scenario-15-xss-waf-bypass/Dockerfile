FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app/
EXPOSE 8015
CMD ["gunicorn", "--workers=4", "--threads=4", "--worker-class=gthread", "--bind=0.0.0.0:8015", "--timeout=60", "app:app"]
