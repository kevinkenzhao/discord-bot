FROM python:3.9.19-alpine
RUN mkdir /discord-bot
COPY . /discord-bot
RUN apk update && apk add g++ gcc libxml2 libxslt-dev
RUN apk add --no-cache \
      chromium \
      nss \
      freetype \
      harfbuzz \
      ca-certificates \
      ttf-freefont \
      nodejs \
      yarn
RUN pip3 install -r /discord-bot/requirements.txt

RUN chmod +x /discord-bot/Discord_URL.py

COPY requests_html.py /usr/local/lib/python3.8/site-packages

CMD [ "python3", "/discord-bot/Discord_URL.py" ]
