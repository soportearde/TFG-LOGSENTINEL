FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY log_normalizer.py .

CMD ["python3", "log_normalizer.py"]
