FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN pip install flask pyotp qrcode[pil]

EXPOSE 5000

CMD ["python", "app.py"]

