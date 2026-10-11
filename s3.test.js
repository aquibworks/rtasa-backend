import boto3

ACCESS_KEY = "YOUR_NEW_ACCESS_KEY"
SECRET_KEY = "YOUR_NEW_SECRET_KEY"

s3 = boto3.client(
    "s3",
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    region_name="ap-south-1"
)

bucket = "justifi-prod-documents"
file_name = "test.txt"

with open(file_name, "w") as f:
    f.write("Production S3 test")

s3.upload_file(file_name, bucket, file_name)

print("Upload successful!")
print(f"https://{bucket}.s3.ap-south-1.amazonaws.com/{file_name}")
