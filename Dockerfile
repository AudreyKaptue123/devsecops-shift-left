FROM python:3.9-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install -r requirements.txt

COPY app/ .

USER root
ENV FLASK_ENV=development
EXPOSE 5000
CMD ["python", "app.py"]
