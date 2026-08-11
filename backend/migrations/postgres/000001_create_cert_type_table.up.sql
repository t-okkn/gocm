CREATE TABLE IF NOT EXISTS m_cert_type (
  cert_type VARCHAR(10) NOT NULL DEFAULT '',
  PRIMARY KEY(cert_type)
);

INSERT INTO m_cert_type (cert_type) VALUES
  ('UNKNOWN'),
  ('CA'),
  ('SERVER'),
  ('CLIENT')
ON CONFLICT (cert_type) DO NOTHING;
