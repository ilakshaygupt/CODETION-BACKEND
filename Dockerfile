
FROM python:latest

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y postgresql-client

COPY . .

EXPOSE 8000

ENV DB_HOST=localhost
ENV DB_PORT=5432
ENV DB_NAME=codetion
ENV DB_USER=admin
ENV DB_PASSWORD=admin

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
