# Dockerfile for Python API
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies for mysqlclient
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    pkg-config

COPY . /app

RUN pip install --upgrade pip \
&& pip install -r requirements.txt

EXPOSE 5000

CMD ["python", "app.py"]
