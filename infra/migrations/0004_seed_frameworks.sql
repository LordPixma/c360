-- Seed data for common compliance frameworks

INSERT OR IGNORE INTO frameworks(id, name, description, version, category) VALUES
('soc2', 'SOC 2', 'System and Organization Controls Type 2 - Trust Services Criteria', '2017', 'security'),
('iso27001', 'ISO 27001', 'Information Security Management Systems', '2022', 'security'),
('gdpr', 'GDPR', 'General Data Protection Regulation', '2018', 'privacy'),
('pci-dss', 'PCI DSS', 'Payment Card Industry Data Security Standard', '4.0', 'security'),
('hipaa', 'HIPAA', 'Health Insurance Portability and Accountability Act', '2013', 'privacy'),
('sox', 'SOX', 'Sarbanes-Oxley Act', '2002', 'financial'),
('nist-csf', 'NIST CSF', 'NIST Cybersecurity Framework', '1.1', 'security'),
('iso27002', 'ISO 27002', 'Code of practice for information security controls', '2022', 'security');