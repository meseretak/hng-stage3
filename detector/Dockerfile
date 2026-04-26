FROM python:3.12-alpine

RUN apk upgrade --no-cache && \
    apk add --no-cache iptables~=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]
