FROM python:3.8.0-alpine
ENV PATH="/scripts:${PATH}"
COPY requirements.txt /requirements.txt
RUN apk add --update --no-cache --virtual .tmp gcc libc-dev linux-headers
RUN pip3 install -r /requirements.txt

COPY ./Discord_URL.py /Discord_URL.py
RUN chmod +x Discord_URL.py

CMD [ "python3", "./Discord_URL.py" ]
