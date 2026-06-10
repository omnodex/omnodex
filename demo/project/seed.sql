CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  company TEXT NOT NULL,
  plan TEXT NOT NULL,
  signup_date TEXT NOT NULL,
  mrr REAL NOT NULL
);

INSERT INTO customers (name, email, company, plan, signup_date, mrr) VALUES
  ('Alice Chen',       'alice.chen@acmecorp.com',       'Acme Corp',        'enterprise', '2025-03-15', 4500.00),
  ('Bob Martinez',     'bob.martinez@globex.com',       'Globex Corporation','enterprise', '2025-06-01', 3200.00),
  ('Carol Johnson',    'carol.johnson@initech.com',     'Initech',          'enterprise', '2025-08-20', 5100.00),
  ('Dave Park',        'dave.park@umbrellacorp.com',    'Umbrella Corp',    'pro',        '2025-09-10', 1200.00),
  ('Eve Washington',   'eve.washington@wayneent.com',   'Wayne Enterprises','enterprise', '2025-11-05', 8900.00),
  ('Frank Liu',        'frank.liu@startupxyz.com',      'Startup XYZ',      'free',       '2026-01-12',    0.00),
  ('Grace Okafor',     'grace.okafor@bigbank.com',      'BigBank Financial','enterprise', '2026-02-28', 6700.00),
  ('Hiro Tanaka',      'hiro.tanaka@techgiants.com',    'TechGiants Inc',   'pro',        '2026-03-15', 1500.00);
