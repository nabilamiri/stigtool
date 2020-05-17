FROM python:3.7-alpine

COPY requirements.txt /

RUN apk add build-base && \
    apk add python3-dev && \
    apk add libffi-dev && \
    apk add openssl-dev && \
    apk add libxml2-dev && \
    apk add --update --no-cache g++ gcc libxslt-dev && \
    pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "/l2s.py" ]