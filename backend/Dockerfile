FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Fresh, isolated DB per container instance — critical for stored-state
# challenges (stored XSS, cache layer) so one team's actions never touch
# another team's instance.
RUN python db.py

EXPOSE 5000
CMD ["python", "app.py", "5000"]
