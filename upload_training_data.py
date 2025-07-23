#!/usr/bin/env python3
"""
Upload existing training data to S3 for the first time.
Run this script once to populate your S3 bucket with training data.
"""

import os
import sys
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("Error: boto3 not installed. Run: pip install boto3")
    print("Install with: pip install boto3")
    sys.exit(1)


def upload_training_data():
    """Upload existing training data to S3."""
    bucket_name = "pqswitch-prod-ml-data"
    
    # Data sources to upload
    data_sources = [
        ("combined_scan_results.json", "training-data/combined_scan_results.json"),
        ("ai_evaluation_comprehensive/", "training-data/ai_evaluation_comprehensive/"),
        ("ai_evaluation_reliable/", "training-data/ai_evaluation_reliable/"),
        ("ai_evaluation_high_conf/", "training-data/ai_evaluation_high_conf/"),
        ("ai_evaluation/", "training-data/ai_evaluation/"),
    ]
    
    try:
        s3 = boto3.client('s3')
        
        # Check if bucket exists
        try:
            s3.head_bucket(Bucket=bucket_name)
            print(f"✅ Bucket {bucket_name} exists")
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                print(f"❌ Bucket {bucket_name} does not exist")
                print("Please create the bucket first or update the bucket name")
                return False
            else:
                print(f"Error checking bucket: {e}")
                return False
        
        uploaded_count = 0
        
        for local_path, s3_path in data_sources:
            local_file = Path(local_path)
            
            if not local_file.exists():
                print(f"⚠️  Skipping {local_path} (not found)")
                continue
                
            if local_file.is_file():
                # Upload single file
                print(f"📤 Uploading {local_path} -> s3://{bucket_name}/{s3_path}")
                try:
                    s3.upload_file(str(local_file), bucket_name, s3_path)
                    uploaded_count += 1
                    print(f"✅ Uploaded {local_path}")
                except ClientError as e:
                    print(f"❌ Error uploading {local_path}: {e}")
                    
            elif local_file.is_dir():
                # Upload directory contents
                print(f"📁 Uploading directory {local_path} -> s3://{bucket_name}/{s3_path}")
                for file_path in local_file.rglob('*'):
                    if file_path.is_file():
                        # Create S3 key preserving directory structure
                        relative_path = file_path.relative_to(local_file)
                        s3_key = f"{s3_path}{relative_path}".replace('\\', '/')
                        
                        print(f"  📤 {file_path} -> s3://{bucket_name}/{s3_key}")
                        try:
                            s3.upload_file(str(file_path), bucket_name, s3_key)
                            uploaded_count += 1
                        except ClientError as e:
                            print(f"  ❌ Error uploading {file_path}: {e}")
        
        print(f"\n🎉 Upload completed! {uploaded_count} files uploaded to s3://{bucket_name}")
        print(f"Your training data is now available for CI/CD workflows")
        return True
        
    except NoCredentialsError:
        print("❌ AWS credentials not configured")
        print("Configure with: aws configure")
        print("Or set environment variables:")
        print("  export AWS_ACCESS_KEY_ID=your_key")
        print("  export AWS_SECRET_ACCESS_KEY=your_secret")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    print("🚀 PQSwitch Training Data Upload")
    print("=" * 40)
    
    # Check if we're in the right directory
    if not Path("combined_scan_results.json").exists():
        print("❌ combined_scan_results.json not found")
        print("Please run this script from the pqswitch-scanner root directory")
        sys.exit(1)
    
    print("📊 Found training data files:")
    data_files = [
        "combined_scan_results.json",
        "ai_evaluation_comprehensive/",
        "ai_evaluation_reliable/",
        "ai_evaluation_high_conf/",
        "ai_evaluation/",
    ]
    
    for file_path in data_files:
        if Path(file_path).exists():
            if Path(file_path).is_file():
                size = Path(file_path).stat().st_size / (1024 * 1024)  # MB
                print(f"  ✅ {file_path} ({size:.1f} MB)")
            else:
                print(f"  ✅ {file_path} (directory)")
        else:
            print(f"  ⚠️  {file_path} (not found)")
    
    print("\n🔑 AWS Configuration:")
    if os.getenv('AWS_ACCESS_KEY_ID'):
        print("  ✅ AWS_ACCESS_KEY_ID set")
    else:
        print("  ❌ AWS_ACCESS_KEY_ID not set")
        
    if os.getenv('AWS_SECRET_ACCESS_KEY'):
        print("  ✅ AWS_SECRET_ACCESS_KEY set")
    else:
        print("  ❌ AWS_SECRET_ACCESS_KEY not set")
    
    print("\n🎯 Target S3 bucket: pqswitch-prod-ml-data")
    
    response = input("\nProceed with upload? (y/N): ")
    if response.lower() != 'y':
        print("Upload cancelled")
        return
    
    success = upload_training_data()
    
    if success:
        print("\n✅ Success! Your training data is now in S3")
        print("GitHub Actions workflows can now download this data for training")
    else:
        print("\n❌ Upload failed")
        sys.exit(1)


if __name__ == '__main__':
    main() 