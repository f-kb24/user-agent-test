FROM python:3.8

WORKDIR /app

COPY . .

RUN pip install -r requirements.txt

#comment this for production
CMD ["flask", "run", "--host=0.0.0.0"]