FROM python:3.8.0-alpine
ENV PATH="/scripts:${PATH}"
COPY /volume2/discord-bot /discord-bot
RUN pip3 install -r /discord-bot/requirements.txt

RUN chmod +x /discord-bot/Discord_URL.py

CMD [ "python3", "/discord-bot/Discord_URL.py" ]
