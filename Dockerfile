FROM python:3.8.0-alpine
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

CMD [ "python3", "/discord-bot/Discord_URL.py" ]
