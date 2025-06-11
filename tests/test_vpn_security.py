"""Test suite for VPN security assessment module."""

import pytest
from src.vpn_security import VPNSecurityAssessment, perform_vpn_security_assessment

def test_check_encryption_strength_secure():
    """Test encryption strength for secure protocols."""
    result = VPNSecurityAssessment.check_encryption_strength('TLS_1_2', 2048)
    assert result['is_secure'] is True
    assert 'secure' in result['recommendation']

def test_check_encryption_strength_weak():
    """Test encryption strength for weak protocols."""
    result = VPNSecurityAssessment.check_encryption_strength('SSLv3', 1024)
    assert result['is_secure'] is False
    assert 'Avoid' in result['recommendation']

def test_detect_protocol_vulnerabilities():
    """Test detection of protocol vulnerabilities."""
    vulnerabilities = VPNSecurityAssessment.detect_protocol_vulnerabilities('SSLv3')
    assert 'POODLE' in vulnerabilities[0]

def test_validate_cipher_suite_secure():
    """Test validation of secure cipher suites."""
    result = VPNSecurityAssessment.validate_cipher_suite('ECDHE-RSA-AES256-GCM-SHA384')
    assert result['is_secure'] is True

def test_validate_cipher_suite_weak():
    """Test validation of weak cipher suites."""
    result = VPNSecurityAssessment.validate_cipher_suite('RC4-SHA')
    assert result['is_secure'] is False

def test_perform_vpn_security_assessment():
    """Test comprehensive VPN security assessment."""
    assessment = perform_vpn_security_assessment('TLS_1_2', 2048, 'ECDHE-RSA-AES256-GCM-SHA384')
    
    assert 'encryption_strength' in assessment
    assert 'protocol_vulnerabilities' in assessment
    assert 'cipher_suite_security' in assessment
    
    assert assessment['encryption_strength']['is_secure'] is True