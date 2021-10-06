FROM python:3.8-alpine AS env

WORKDIR /server
COPY requirements.txt .
RUN set -x \
    && python3 -m pip install --no-cache-dir -r ./requirements.txt

FROM env AS production
COPY . .
CMD ["python3","./Server.py"]