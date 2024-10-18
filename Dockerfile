
FROM python:3.9

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y postgresql-client
COPY . .

EXPOSE 8003

ENV DB_HOST=postgres
ENV DB_PORT=5432
ENV DB_NAME=codetion
ENV DB_USER=codetion
ENV DB_PASSWORD=codetion

CMD ["python", "manage.py", "runserver", "0.0.0.0:8003"]
