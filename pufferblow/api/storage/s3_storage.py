"""
AWS S3 Storage Backend for Pufferblow

Provides AWS S3 cloud storage backend with signed URLs and bucket management.
"""

import boto3
import botocore.exceptions
from typing import Optional, Dict, Any, List
from fastapi import HTTPException

from .storage_backend import StorageBackend


class S3StorageBackend(StorageBackend):
    """AWS S3 storage backend"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        # S3 configuration
        self.bucket_name = config.get("bucket_name")
        if not self.bucket_name:
            raise ValueError("bucket_name is required for S3 storage")

        self.region = config.get("region", "us-east-1")
        self.access_key = config.get("access_key")
        self.secret_key = config.get("secret_key")
        self.endpoint_url = config.get("endpoint_url")  # For custom S3-compatible services
        self.base_url = config.get("base_url")  # Custom base URL if needed
        self.api_host = config.get("api_host", "127.0.0.1")
        self.api_port = config.get("api_port", 7575)

        # Create S3 client
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
            endpoint_url=self.endpoint_url
        )

        # Test connection
        self._test_connection()

    def _test_connection(self):
        """Test S3 connection and bucket access"""
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '403':
                raise ValueError(f"No access to bucket '{self.bucket_name}'")
            elif error_code == '404':
                raise ValueError(f"Bucket '{self.bucket_name}' does not exist")
            else:
                raise ValueError(f"S3 connection failed: {e}")

    async def upload_file(self, content: bytes, path: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Upload file to S3"""
        try:
            # Prepare metadata
            s3_metadata = {}
            if metadata:
                # Convert metadata to string values as required by S3
                s3_metadata = {k: str(v) for k, v in metadata.items()}

            # Upload file
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=path,
                Body=content,
                Metadata=s3_metadata
            )

            # Return full URL instead of just path
            return await self.get_file_url(path)

        except botocore.exceptions.ClientError as e:
            raise HTTPException(
                status_code=500,
                detail=f"S3 upload failed: {e.response['Error']['Message']}"
            )

    async def download_file(self, path: str) -> bytes:
        """Download file from S3"""
        try:
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=path)
            return response['Body'].read()
        except self.s3_client.exceptions.NoSuchKey:
            raise HTTPException(status_code=404, detail="File not found")
        except botocore.exceptions.ClientError as e:
            raise HTTPException(
                status_code=500,
                detail=f"S3 download failed: {e.response['Error']['Message']}"
            )

    async def delete_file(self, path: str) -> bool:
        """Delete file from S3"""
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=path)
            return True
        except botocore.exceptions.ClientError:
            return False

    async def file_exists(self, path: str) -> bool:
        """Check if file exists in S3"""
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=path)
            return True
        except self.s3_client.exceptions.NoSuchKey:
            return False
        except botocore.exceptions.ClientError:
            return False

    async def get_file_url(self, path: str, expires_in: Optional[int] = None) -> str:
        """Get signed URL for S3 file"""
        try:
            if expires_in:
                # Generate signed URL
                url = self.s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': self.bucket_name, 'Key': path},
                    ExpiresIn=expires_in
                )
            else:
                # Use public URL (assumes bucket/objects are public)
                if self.endpoint_url:
                    url = f"{self.endpoint_url}/{self.bucket_name}/{path}"
                else:
                    url = f"https://{self.bucket_name}.s3.{self.region}.amazonaws.com/{path}"

            return url

        except botocore.exceptions.ClientError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to generate S3 URL: {e.response['Error']['Message']}"
            )

    async def list_files(self, prefix: str = "") -> List[str]:
        """List files in S3 with prefix"""
        try:
            files = []
            paginator = self.s3_client.get_paginator('list_objects_v2')

            for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix):
                if 'Contents' in page:
                    for obj in page['Contents']:
                        files.append(obj['Key'])

            return files

        except botocore.exceptions.ClientError as e:
            raise HTTPException(
                status_code=500,
                detail=f"S3 list failed: {e.response['Error']['Message']}"
            )

    async def get_storage_info(self) -> Dict[str, Any]:
        """Get S3 storage information"""
        try:
            # Get bucket location
            location = self.s3_client.get_bucket_location(Bucket=self.bucket_name)
            region = location.get('LocationConstraint', 'us-east-1')

            # Count objects and calculate size (this is expensive for large buckets)
            total_size = 0
            total_objects = 0

            paginator = self.s3_client.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=self.bucket_name):
                if 'Contents' in page:
                    for obj in page['Contents']:
                        total_size += obj['Size']
                        total_objects += 1

            return {
                "provider": "s3",
                "bucket_name": self.bucket_name,
                "region": region,
                "endpoint_url": self.endpoint_url,
                "total_objects": total_objects,
                "total_size_gb": total_size / (1024**3),
                "total_size_bytes": total_size
            }

        except botocore.exceptions.ClientError as e:
            return {
                "provider": "s3",
                "bucket_name": self.bucket_name,
                "error": f"Failed to get storage info: {e.response['Error']['Message']}"
            }

    async def check_space_available(self, size_bytes: int) -> bool:
        """S3 doesn't have strict space limits like local storage"""
        # AWS S3 has very high limits, so we consider space always available
        # In a production system, you might want to check against account limits
        return True
