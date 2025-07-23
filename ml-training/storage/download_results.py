#!/usr/bin/env python3
"""
Download training data from S3 for ML model training.
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


def download_from_s3(bucket_name, target_dir, latest_only=False):
    """Download training data from S3 bucket."""
    try:
        s3 = boto3.client('s3')
        
        # Create target directory
        Path(target_dir).mkdir(parents=True, exist_ok=True)
        
        # Test bucket access first
        try:
            print(f"🧪 Testing access to bucket {bucket_name}...")
            s3.head_bucket(Bucket=bucket_name)
            print(f"✅ Bucket {bucket_name} is accessible")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                print(f"❌ Bucket {bucket_name} does not exist")
            elif error_code == 'AccessDenied':
                print(f"❌ Access denied to bucket {bucket_name}")
                print("💡 Your AWS credentials may need s3:ListBucket permission")
            else:
                print(f"❌ Error accessing bucket {bucket_name}: {error_code}")
            return False
        
        # List objects in bucket
        try:
            print(f"📋 Listing objects with prefix 'training-data/'...")
            response = s3.list_objects_v2(Bucket=bucket_name, Prefix='training-data/')
            
            if 'Contents' not in response:
                print(f"📭 No training data found in bucket {bucket_name}")
                print("💡 This is normal for initial setup - sample data will be used")
                return False
                
            objects = response['Contents']
            print(f"📦 Found {len(objects)} objects in bucket")
            
            # Sort by last modified if latest_only
            if latest_only:
                objects = sorted(objects, key=lambda x: x['LastModified'], reverse=True)
                objects = objects[:10]  # Take latest 10 files
                print(f"🔄 Limited to latest {len(objects)} files")
            
            downloaded = 0
            for obj in objects:
                key = obj['Key']
                if key.endswith('.json'):
                    local_path = Path(target_dir) / Path(key).name
                    
                    print(f"📥 Downloading {key} -> {local_path}")
                    try:
                        s3.download_file(bucket_name, key, str(local_path))
                        downloaded += 1
                        print(f"  ✅ Downloaded successfully")
                    except ClientError as e:
                        print(f"  ❌ Download failed: {e}")
                        
            print(f"📊 Downloaded {downloaded} files to {target_dir}")
            return downloaded > 0
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                print(f"❌ Access denied when listing objects in bucket {bucket_name}")
                print("💡 Your AWS credentials may need s3:ListBucket permission")
            else:
                print(f"❌ Error listing objects: {error_code}")
            return False
                
    except NoCredentialsError:
        print("❌ AWS credentials not configured")
        print("💡 Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Download training data from S3')
    parser.add_argument('--bucket', required=True, help='S3 bucket name')
    parser.add_argument('--target', required=True, help='Target directory for downloads')
    parser.add_argument('--latest-only', action='store_true', help='Download only latest files')
    
    args = parser.parse_args()
    
    success = download_from_s3(args.bucket, args.target, args.latest_only)
    
    if not success:
        print("Download failed or no data found")
        sys.exit(1)
    
    print("Download completed successfully")


if __name__ == '__main__':
    main() 