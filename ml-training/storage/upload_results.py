#!/usr/bin/env python3
"""
Upload training results to S3 for ML model storage.
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("Error: boto3 not installed. Run: pip install boto3")
    sys.exit(1)


def upload_to_s3(results_dir, bucket_name, target_prefix=""):
    """Upload training results to S3 bucket."""
    try:
        s3 = boto3.client('s3')
        
        results_path = Path(results_dir)
        if not results_path.exists():
            print(f"Results directory {results_dir} does not exist")
            return False
            
        # Upload all files in the directory
        uploaded = 0
        for file_path in results_path.rglob('*'):
            if file_path.is_file():
                # Create S3 key
                relative_path = file_path.relative_to(results_path)
                s3_key = f"{target_prefix}/{relative_path}" if target_prefix else str(relative_path)
                s3_key = s3_key.replace('\\', '/')  # Ensure forward slashes
                
                print(f"Uploading {file_path} -> s3://{bucket_name}/{s3_key}")
                
                try:
                    s3.upload_file(str(file_path), bucket_name, s3_key)
                    uploaded += 1
                except ClientError as e:
                    print(f"Error uploading {file_path}: {e}")
                    
        print(f"Uploaded {uploaded} files to s3://{bucket_name}/{target_prefix}")
        return uploaded > 0
        
    except NoCredentialsError:
        print("Error: AWS credentials not configured")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Upload training results to S3')
    parser.add_argument('--results-dir', required=True, help='Directory containing results to upload')
    parser.add_argument('--bucket', required=True, help='S3 bucket name')
    parser.add_argument('--target-prefix', default='', help='S3 prefix for uploaded files')
    
    args = parser.parse_args()
    
    success = upload_to_s3(args.results_dir, args.bucket, args.target_prefix)
    
    if not success:
        print("Upload failed")
        sys.exit(1)
    
    print("Upload completed successfully")


if __name__ == '__main__':
    main() 