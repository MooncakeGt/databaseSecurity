import os

class Config:
    # AWS Configuration
    AWS_REGION = "ap-southeast-1"
    AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID", "your-access-key-id")
    AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "your-secret-access-key")
    
    # S3 Configuration
    S3_BUCKET_NAME = "assignment-secure-app-bucket"

    # RDS Configuration (MySQL)
    DB_HOST = os.getenv("DB_HOST", "asg2-rds.c778dhky41n9.us-east-1.rds.amazonaws.com")
    DB_NAME = "AsgmtDB"
    DB_USER = "admin"
    DB_PASSWORD = os.getenv("DB_PASSWORD", "StrongPass123!")

    # Other settings
    DEBUG = True
