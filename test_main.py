import os
import time
import pytest
from main import (
    derive_key,
    encrypt,
    decrypt,
    secure_delete,
    save_encrypted_note,
    read_encrypted_note,
    parse_duration,
    pad,
    unpad
)

# Test data
TEST_KEY = "test_password123"
TEST_MESSAGE = "This is a secret message!"
TEST_FILE = "test_note.sec"
SHORT_TEST_FILE = "short_test.sec"

@pytest.fixture(autouse=True)
def cleanup_files():
    """Clean up test files after each test."""
    yield
    for file in [TEST_FILE, SHORT_TEST_FILE]:
        if os.path.exists(file):
            os.remove(file)

def test_derive_key():
    """Test key derivation produces consistent 32-byte output."""
    key1 = derive_key(TEST_KEY)
    key2 = derive_key(TEST_KEY)
    key3 = derive_key("different_password")
    
    assert len(key1) == 32  # AES-256 key length
    assert key1 == key2
    assert key1 != key3

def test_pad_unpad():
    """Test padding and unpadding functions."""
    test_string = "test string"
    padded = pad(test_string)
    unpadded = unpad(padded)
    
    assert len(padded) % 16 == 0  # Block size alignment
    assert unpadded == test_string

def test_encrypt_decrypt():
    """Test encryption and decryption round-trip."""
    encrypted = encrypt(TEST_MESSAGE, TEST_KEY)
    decrypted = decrypt(encrypted, TEST_KEY)
    
    assert encrypted != TEST_MESSAGE
    assert decrypted == TEST_MESSAGE

def test_encrypt_decrypt_with_special_chars():
    """Test encryption with special characters."""
    message = "Special chars: !@#$%^&*()"
    encrypted = encrypt(message, TEST_KEY)
    decrypted = decrypt(encrypted, TEST_KEY)
    
    assert decrypted == message

def test_save_and_read_note():
    """Test saving and reading a note before expiration."""
    expiry = 10  # 10s in future
    save_encrypted_note(TEST_FILE, TEST_MESSAGE, TEST_KEY, expiry)
    
    # Reading immediately (should work)
    read_encrypted_note(TEST_FILE, TEST_KEY)
    assert not os.path.exists(TEST_FILE)  # File should be deleted after reading

def test_expired_note():
    """Test that expired notes are deleted."""
    expiry = 1  # 1s in future
    save_encrypted_note(SHORT_TEST_FILE, TEST_MESSAGE, TEST_KEY, expiry)
    
    # Waiting for expiration
    time.sleep(1.1)
    
    # Attempting to read (should fail and delete file)
    read_encrypted_note(SHORT_TEST_FILE, TEST_KEY)
    assert not os.path.exists(SHORT_TEST_FILE)

def test_secure_delete():
    """Test secure file deletion."""
    test_content = "test content"
    with open(TEST_FILE, "w") as f:
        f.write(test_content)
    
    secure_delete(TEST_FILE)
    assert not os.path.exists(TEST_FILE)

def test_parse_duration():
    """Test duration string parsing."""
    assert parse_duration("60") == 60  # Default
    assert parse_duration("30") == 30
    assert parse_duration("5m") == 300
    assert parse_duration("2h") == 7200
    assert parse_duration("1d") == 86400

def test_wrong_key_decryption():
    """Test decryption with wrong key fails."""
    encrypted = encrypt(TEST_MESSAGE, TEST_KEY)
    
    decrypted = decrypt(encrypted, "wrong_password")
    
    assert decrypted != TEST_MESSAGE

def test_missing_file_decryption(capsys):
    """Test handling of missing file."""
    read_encrypted_note("nonexistent_file.sec", TEST_KEY)
    
    captured = capsys.readouterr()
    
    assert "❌ Error: [Errno 2] No such file or directory: 'nonexistent_file.sec'" in captured.out

def test_empty_message():
    """Test handling of empty message."""
    save_encrypted_note(TEST_FILE, "", TEST_KEY, 10)
    read_encrypted_note(TEST_FILE, TEST_KEY)
    assert not os.path.exists(TEST_FILE)

def test_long_message():
    """Test handling of long message (multi-block)."""
    long_message = "A" * 5000  # Longer than one block
    save_encrypted_note(TEST_FILE, long_message, TEST_KEY, 10)
    read_encrypted_note(TEST_FILE, TEST_KEY)
    assert not os.path.exists(TEST_FILE)