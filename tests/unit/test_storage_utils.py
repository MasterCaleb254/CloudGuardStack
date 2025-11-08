# tests/unit/test_storage_utils.py
import pytest
import hashlib
from datetime import timezone
from datetime import datetime, timedelta, date
from datetime import datetime, timedelta, timezone
from scanners.storage_auditor.utils import (
    is_valid_bucket_name,
    generate_bucket_etag,
    format_size,
    parse_s3_arn,
    is_expired,
    deep_merge,
    json_serial,
    safe_get
)

# Test is_valid_bucket_name
def test_is_valid_bucket_name():
    """Test bucket name validation."""
    # Valid names
    assert is_valid_bucket_name("valid-bucket-name")
    assert is_valid_bucket_name("valid.bucket.name")
    assert is_valid_bucket_name("valid123")
    assert is_valid_bucket_name("a" * 63)  # Max length
    
    # Invalid names
    assert not is_valid_bucket_name("")  # Too short
    assert not is_valid_bucket_name("a" * 64)  # Too long
    assert not is_valid_bucket_name("InvalidBucket")  # Uppercase
    assert not is_valid_bucket_name("invalid..bucket")  # Double dots
    assert not is_valid_bucket_name("-invalid-bucket")  # Starts with hyphen
    assert not is_valid_bucket_name("invalid-bucket-")  # Ends with hyphen
    assert not is_valid_bucket_name("192.168.1.1")  # IP address format
    assert not is_valid_bucket_name("xn--invalid")  # Starts with xn--
    assert not is_valid_bucket_name("invalid-s3alias")  # Ends with -s3alias
    assert not is_valid_bucket_name("invalid/bucket")  # Contains invalid character
    assert not is_valid_bucket_name(None)  # Not a string

# Test generate_bucket_etag
def test_generate_bucket_etag():
    """Test ETag generation."""
    test_data = "test data"
    expected_hash = hashlib.md5(test_data.encode('utf-8')).hexdigest()
    
    # Test with string input
    assert generate_bucket_etag(test_data) == expected_hash
    
    # Test with bytes input
    assert generate_bucket_etag(test_data.encode('utf-8')) == expected_hash

# Test format_size
def test_format_size():
    """Test size formatting."""
    assert format_size(0) == "0.0 B"
    assert format_size(1023) == "1023.0 B"
    assert format_size(1024) == "1.0 KB"
    assert format_size(1024 * 1024) == "1.0 MB"
    assert format_size(1024 * 1024 * 1024) == "1.0 GB"
    assert format_size(1024 * 1024 * 1024 * 1024) == "1.0 TB"
    assert format_size(1024 * 1024 * 1024 * 1024 * 1024) == "1024.0 TB"  # PB not reached

# Test parse_s3_arn
def test_parse_s3_arn():
    """Test S3 ARN parsing."""
    # Test bucket ARN
    arn = "arn:aws:s3:::my-bucket"
    result = parse_s3_arn(arn)
    assert result == {
        'partition': 'aws',
        'service': 's3',
        'region': '',
        'account': '',
        'resource': 'my-bucket',
        'bucket': 'my-bucket',
        'key': ''
    }
    
    # Test object ARN
    arn = "arn:aws:s3:::my-bucket/path/to/object.txt"
    result = parse_s3_arn(arn)
    assert result == {
        'partition': 'aws',
        'service': 's3',
        'region': '',
        'account': '',
        'resource': 'my-bucket/path/to/object.txt',
        'bucket': 'my-bucket',
        'key': 'path/to/object.txt'
    }
    
    # Test with region and account
    arn = "arn:aws:s3:us-east-1:123456789012:my-bucket"
    result = parse_s3_arn(arn)
    assert result['region'] == 'us-east-1'
    assert result['account'] == '123456789012'
    
    # Test invalid ARNs
    with pytest.raises(ValueError, match="Invalid S3 ARN"):
        parse_s3_arn("invalid-arn")
    
    with pytest.raises(ValueError, match="Invalid S3 ARN format"):
        parse_s3_arn("arn:aws:s3:")

# Test is_expired
def test_is_expired():
    # Test with datetime object
    now = datetime.now(timezone.utc)
    recent = now - timedelta(days=1)
    old = now - timedelta(days=31)
    
    assert not is_expired(recent, days=30)
    assert is_expired(old, days=30)
    
    # Test with timestamp
    assert not is_expired(recent.timestamp(), days=30)
    assert is_expired(old.timestamp(), days=30)
    
    # Test with string timestamp
    assert not is_expired(recent.isoformat(), days=30)
    assert is_expired(old.isoformat(), days=30)
    
    # Test with invalid timestamp
    with pytest.raises(TypeError):
        is_expired("invalid-timestamp")

# Test deep_merge
def test_deep_merge():
    """Test deep dictionary merge."""
    dict1 = {
        'a': 1,
        'b': {
            'c': 2,
            'd': [1, 2, 3]
        }
    }
    
    dict2 = {
        'b': {
            'd': [4, 5, 6],
            'e': 3
        },
        'f': 4
    }
    
    expected = {
        'a': 1,
        'b': {
            'c': 2,
            'd': [4, 5, 6],  # Overwritten by dict2
            'e': 3
        },
        'f': 4
    }
    
    assert deep_merge(dict1, dict2) == expected
    
    # Test with empty dictionaries
    assert deep_merge({}, {'a': 1}) == {'a': 1}
    assert deep_merge({'a': 1}, {}) == {'a': 1}

# Test json_serial
def test_json_serial():
    """Test JSON serialization of non-standard types."""
    # Test with datetime
    dt = datetime(2023, 1, 1, 12, 0, 0)
    assert json_serial(dt) == "2023-01-01T12:00:00"
    
    # Test with date
    d = date(2023, 1, 1)
    assert json_serial(d) == "2023-01-01T00:00:00"
    
    # Test with unsupported type
    with pytest.raises(TypeError):
        json_serial({"key": "value"})

# Test safe_get
def test_safe_get():
    """Test safe dictionary access."""
    test_dict = {
        'a': {
            'b': {
                'c': 123
            },
            'd': [1, 2, 3]
        }
    }
    
    # Test existing path
    assert safe_get(test_dict, 'a', 'b', 'c') == 123
    
    # Test non-existent path
    assert safe_get(test_dict, 'x', 'y', 'z') is None
    assert safe_get(test_dict, 'a', 'x', 'y') is None
    
    # Test with default value
    assert safe_get(test_dict, 'x', 'y', 'z', default=42) == 42
    
    # Test with empty path
    assert safe_get(test_dict) == test_dict
    
    # Test with non-dictionary input
    assert safe_get(None, 'a', 'b') is None
    assert safe_get("not-a-dict", 'a') is None