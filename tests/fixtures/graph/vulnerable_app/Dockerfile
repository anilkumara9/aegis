FROM python:3.12-slim
WORKDIR /srv/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# NOTE: no USER directive — container runs as root (fixture signal).
CMD ["gunicorn", "app:app"]
