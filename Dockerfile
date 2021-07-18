FROM python:3.8.0-alpine
RUN mkdir /discord-bot
COPY . /discord-bot
RUN pip3 install -r /discord-bot/requirements.txt

RUN chmod +x /discord-bot/Discord_URL.py

CMD [ "python3", "/discord-bot/Discord_URL.py" ]
