FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN rm -f wajh_model.joblib && \
    apt-get update && apt-get install -y curl && \
    curl -L -o wajh_model.joblib "https://media.githubusercontent.com/media/malakmoaaz/wajh-backend/master/python/wajh_model.joblib"
EXPOSE 7860
CMD ["uvicorn", "ml_server:app", "--host", "0.0.0.0", "--port", "7860"]
