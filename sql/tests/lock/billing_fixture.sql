\set ON_ERROR_STOP on
TRUNCATE api_keys, billing_orders, billing_events RESTART IDENTITY CASCADE;
INSERT INTO api_keys (key_hash) VALUES (repeat('c', 64));
INSERT INTO billing_orders (provider, provider_order_ref, order_id, status, claimable_until, claimed_at, api_key_id)
SELECT 'lemonsqueezy', '5001', 'c0000000-0000-4000-8000-000000005001', 'regenerating', now() + interval '24 hours', now(), ak.id
  FROM api_keys AS ak
 WHERE ak.key_hash = repeat('c', 64);
