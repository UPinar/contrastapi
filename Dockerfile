FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY mcp_server.py .

EXPOSE 8002

CMD ["python3", "mcp_server.py"]
