FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY correlator.py .
COPY rules ./rules

EXPOSE 7000

CMD ["python3", "correlator.py"]
