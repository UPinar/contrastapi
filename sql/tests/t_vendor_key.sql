CREATE FUNCTION pg_temp.t_vk_hash(p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT 'f5' || lpad(to_hex(p_n), 62, '0')
$$;

CREATE FUNCTION pg_temp.t_vk_th(p_t integer) RETURNS text LANGUAGE sql AS $$
  SELECT 'e7' || lpad(to_hex(p_t), 62, '0')
$$;

CREATE FUNCTION pg_temp.t_vk_id(p_n integer) RETURNS integer LANGUAGE sql AS $$
  SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = pg_temp.t_vk_hash(p_n)
$$;

CREATE FUNCTION pg_temp.t_vk_fp(p_key_hash text) RETURNS text LANGUAGE sql AS $$
  SELECT left(encode(sha256(convert_to(p_key_hash, 'UTF8')), 'hex'), 32)
$$;

CREATE FUNCTION pg_temp.t_vk_fpn(p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT pg_temp.t_vk_fp(pg_temp.t_vk_hash(p_n))
$$;

CREATE FUNCTION pg_temp.t_vk_key(p_n integer, p_active boolean, p_expires_at timestamptz) RETURNS void LANGUAGE sql AS $$
  INSERT INTO api_keys (key_hash, active, expires_at) VALUES (pg_temp.t_vk_hash(p_n), p_active, p_expires_at)
$$;

CREATE FUNCTION pg_temp.t_vk_sealed(p_n integer, p_vendor_name text) RETURNS text LANGUAGE sql AS $$
  SELECT CASE p_vendor_name WHEN 'shodan' THEN 'a' ELSE 'b' END || lpad(to_hex(p_n), 3, '0') || repeat('0', 76)
$$;

CREATE FUNCTION pg_temp.t_vk_store(p_n integer, p_vendor_name text) RETURNS void LANGUAGE sql AS $$
  INSERT INTO vendor_key (api_key_id, vendor_name, sealed_hex)
  VALUES (pg_temp.t_vk_id(p_n), p_vendor_name, pg_temp.t_vk_sealed(p_n, p_vendor_name))
$$;

CREATE FUNCTION pg_temp.t_vk_store_link(p_t integer, p_n integer, p_expires_at timestamptz) RETURNS void LANGUAGE sql AS $$
  INSERT INTO vendor_key_link (link_hash, api_key_id, key_fingerprint, expires_at)
  VALUES (pg_temp.t_vk_th(p_t), pg_temp.t_vk_id(p_n), pg_temp.t_vk_fpn(p_n), p_expires_at)
$$;

CREATE FUNCTION pg_temp.t_vk_read(p_key_hash text) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(coalesce(r.api_key_id::text, 'null') || '|' || coalesce(r.key_fingerprint, 'null')
                             || '|' || coalesce(r.shodan_sealed_hex, 'null') || '|' || coalesce(r.abuseipdb_sealed_hex, 'null'), ','), '')
    FROM api.fn_vendor_key_read(p_key_hash) AS r
$$;

CREATE FUNCTION pg_temp.t_vk_link_read(p_link_hash text) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(coalesce(r.link_state, 'null') || '|' || coalesce(r.api_key_id::text, 'null')
                             || '|' || coalesce(r.link_expires_at::text, 'null')
                             || '|' || coalesce(r.shodan_sealed_hex, 'null') || '|' || coalesce(r.abuseipdb_sealed_hex, 'null'), ','), '')
    FROM api.fn_vendor_key_link_read(p_link_hash) AS r
$$;

CREATE FUNCTION pg_temp.t_vk_open_answer(p_n integer, p_end bigint, p_shodan boolean, p_abuseipdb boolean) RETURNS text LANGUAGE sql AS $$
  SELECT 'open|' || pg_temp.t_vk_id(p_n) || '|' || p_end
         || '|' || CASE WHEN p_shodan THEN pg_temp.t_vk_sealed(p_n, 'shodan') ELSE 'null' END
         || '|' || CASE WHEN p_abuseipdb THEN pg_temp.t_vk_sealed(p_n, 'abuseipdb') ELSE 'null' END
$$;

CREATE FUNCTION pg_temp.t_vk_answer(p_n integer, p_shodan boolean, p_abuseipdb boolean) RETURNS text LANGUAGE sql AS $$
  SELECT pg_temp.t_vk_id(p_n)::text || '|' || pg_temp.t_vk_fpn(p_n)
         || '|' || CASE WHEN p_shodan THEN pg_temp.t_vk_sealed(p_n, 'shodan') ELSE 'null' END
         || '|' || CASE WHEN p_abuseipdb THEN pg_temp.t_vk_sealed(p_n, 'abuseipdb') ELSE 'null' END
$$;

CREATE FUNCTION pg_temp.t_vk_rows(p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(vk.vendor_name || '=' || vk.sealed_hex, ',' ORDER BY vk.vendor_name), '')
    FROM vendor_key AS vk WHERE vk.api_key_id = pg_temp.t_vk_id(p_n)
$$;

CREATE FUNCTION pg_temp.t_vk_links_of(p_api_key_id integer) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(vkl.link_hash || '|' || vkl.key_fingerprint || '|' || floor(extract(epoch FROM vkl.expires_at))::bigint, ','
                             ORDER BY vkl.link_hash), '')
    FROM vendor_key_link AS vkl WHERE vkl.api_key_id = p_api_key_id
$$;

CREATE FUNCTION pg_temp.t_vk_links(p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT pg_temp.t_vk_links_of(pg_temp.t_vk_id(p_n))
$$;

CREATE FUNCTION pg_temp.t_vk_link_row(p_t integer, p_n integer, p_end bigint) RETURNS text LANGUAGE sql AS $$
  SELECT pg_temp.t_vk_th(p_t) || '|' || pg_temp.t_vk_fpn(p_n) || '|' || p_end
$$;

CREATE FUNCTION pg_temp.t_vk_has_link(p_t integer) RETURNS boolean LANGUAGE sql AS $$
  SELECT EXISTS (SELECT 1 FROM vendor_key_link AS vkl WHERE vkl.link_hash = pg_temp.t_vk_th(p_t))
$$;

CREATE FUNCTION pg_temp.t_vk_snapshot() RETURNS text LANGUAGE sql AS $$
  SELECT coalesce((SELECT string_agg(vk.api_key_id || ' ' || vk.vendor_name || ' ' || vk.sealed_hex || ' ' || vk.saved_at,
                                     ',' ORDER BY vk.api_key_id, vk.vendor_name)
                     FROM vendor_key AS vk), '')
         || ';' ||
         coalesce((SELECT string_agg(vkl.link_hash || ' ' || vkl.api_key_id || ' ' || vkl.key_fingerprint || ' ' || vkl.expires_at, ',' ORDER BY vkl.link_hash)
                     FROM vendor_key_link AS vkl), '')
$$;

SELECT pg_temp.t_vk_key(1,  true,  NULL);
SELECT pg_temp.t_vk_key(2,  true,  now() + interval '1 day');
SELECT pg_temp.t_vk_key(3,  false, NULL);
SELECT pg_temp.t_vk_key(4,  true,  now() - interval '1 second');
SELECT pg_temp.t_vk_key(5,  true,  NULL);
SELECT pg_temp.t_vk_key(6,  true,  NULL);
SELECT pg_temp.t_vk_key(7,  true,  NULL);
SELECT pg_temp.t_vk_key(12, true,  NULL);
SELECT pg_temp.t_vk_key(13, true,  NULL);
SELECT pg_temp.t_vk_store(1, 'shodan'), pg_temp.t_vk_store(1, 'abuseipdb');
SELECT pg_temp.t_vk_store(2, 'shodan'), pg_temp.t_vk_store(2, 'abuseipdb');
SELECT pg_temp.t_vk_store(3, 'shodan'), pg_temp.t_vk_store(3, 'abuseipdb');
SELECT pg_temp.t_vk_store(4, 'shodan'), pg_temp.t_vk_store(4, 'abuseipdb');
SELECT pg_temp.t_vk_store(6, 'abuseipdb');
SELECT pg_temp.t_vk_store(7, 'shodan');
SELECT pg_temp.t_vk_store(12, 'shodan');
SELECT pg_temp.t_vk_store(13, 'shodan');
SELECT pg_temp.t_vk_store_link(1,  1,  to_timestamp(1893456000));
SELECT pg_temp.t_vk_store_link(2,  2,  to_timestamp(1893456000));
SELECT pg_temp.t_vk_store_link(3,  3,  to_timestamp(1893456000));
SELECT pg_temp.t_vk_store_link(4,  4,  to_timestamp(1893456000));
SELECT pg_temp.t_vk_store_link(5,  5,  to_timestamp(1893456000));
SELECT pg_temp.t_vk_store_link(6,  6,  to_timestamp(1893456000));
SELECT pg_temp.t_vk_store_link(7,  7,  to_timestamp(1893456000));
SELECT pg_temp.t_vk_store_link(13, 13, now() - interval '1 hour');
INSERT INTO vendor_key_link (link_hash, api_key_id, key_fingerprint, expires_at)
  VALUES (pg_temp.t_vk_th(14), pg_temp.t_vk_id(1), pg_temp.t_vk_fpn(2), to_timestamp(1893456000));
SELECT pg_temp.t_vk_store_link(15, 1,  now());
SELECT pg_temp.t_vk_store_link(16, 1,  now() + interval '1 second');
SELECT pg_temp.t_vk_store_link(17, 3,  now() - interval '1 hour');

CREATE TEMP TABLE t_vk_decoy AS SELECT pg_temp.t_vk_rows(2) || ';' || pg_temp.t_vk_links(2) AS decoy_state;

SELECT pg_temp.t_vk_hash(1) AS t_vk_hash_1, pg_temp.t_vk_id(1) AS t_vk_id_1, pg_temp.t_vk_fpn(1) AS t_vk_fp_1,
       pg_temp.t_vk_id(3) AS t_vk_id_3, pg_temp.t_vk_th(1) AS t_vk_th_1, pg_temp.t_vk_th(9001) AS t_vk_th_9001 \gset

PREPARE t_vk_read_query AS SELECT * FROM api.fn_vendor_key_read($1);
PREPARE t_vk_open_query AS SELECT api.fn_vendor_key_link_open($1, $2, $3) AS link_expires_at;
PREPARE t_vk_link_read_query AS SELECT * FROM api.fn_vendor_key_link_read($1);
PREPARE t_vk_apply_query AS SELECT api.fn_vendor_key_apply($1, $2, $3, $4, $5, $6, $7, $8) AS apply_status;
PREPARE t_vk_purge_query AS SELECT api.fn_vendor_key_purge($1) AS purged_key_count;
PREPARE t_vk_link_purge_query AS SELECT api.fn_vendor_key_link_purge($1) AS purged_link_count;
CREATE TEMP TABLE t_vk_param_types AS
  SELECT ps.name, ps.parameter_types::text AS parameter_types FROM pg_prepared_statements AS ps WHERE ps.name LIKE 't_vk_%';
CREATE TEMP TABLE t_vk_read_answer AS EXECUTE t_vk_read_query(:'t_vk_hash_1');
CREATE TEMP TABLE t_vk_open_answer AS EXECUTE t_vk_open_query(:'t_vk_id_3', :'t_vk_th_9001', '900');
CREATE TEMP TABLE t_vk_link_read_answer AS EXECUTE t_vk_link_read_query(:'t_vk_th_1');
CREATE TEMP TABLE t_vk_apply_answer AS EXECUTE t_vk_apply_query(:'t_vk_id_1', NULL, :'t_vk_fp_1', 'false', NULL, 'false', NULL, 'false');
CREATE TEMP TABLE t_vk_purge_answer AS EXECUTE t_vk_purge_query('0');
CREATE TEMP TABLE t_vk_link_purge_answer AS EXECUTE t_vk_link_purge_query('0');
DEALLOCATE t_vk_read_query;
DEALLOCATE t_vk_open_query;
DEALLOCATE t_vk_link_read_query;
DEALLOCATE t_vk_apply_query;
DEALLOCATE t_vk_purge_query;
DEALLOCATE t_vk_link_purge_query;

CREATE FUNCTION pg_temp.t_vk_columns(p_table regclass) RETURNS text[] LANGUAGE sql AS $$
  SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
    FROM pg_attribute WHERE attrelid = p_table AND attnum > 0
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(pt.name || ' ' || pt.parameter_types ORDER BY pt.name) FROM t_vk_param_types AS pt)
         = ARRAY['t_vk_apply_query {integer,text,text,boolean,text,boolean,text,boolean}',
                 't_vk_link_purge_query {integer}',
                 't_vk_link_read_query {text}',
                 't_vk_open_query {integer,text,integer}',
                 't_vk_purge_query {integer}',
                 't_vk_read_query {text}'],
         'the untyped parameters of each call take the types of its function';
  ASSERT pg_temp.t_vk_columns('t_vk_read_answer') = ARRAY['api_key_id integer', 'key_fingerprint text', 'shodan_sealed_hex text', 'abuseipdb_sealed_hex text'],
         'the read call answers api_key_id integer, key_fingerprint text, shodan_sealed_hex text, abuseipdb_sealed_hex text';
  ASSERT (SELECT array_agg(r.api_key_id || '|' || r.key_fingerprint || '|' || r.shodan_sealed_hex || '|' || r.abuseipdb_sealed_hex) FROM t_vk_read_answer AS r)
         = ARRAY[pg_temp.t_vk_answer(1, true, true)],
         'the read call answers the one row of the key 1';
  ASSERT pg_temp.t_vk_columns('t_vk_open_answer') = ARRAY['link_expires_at bigint'], 'the open call answers one bigint column';
  ASSERT (SELECT array_agg(r.link_expires_at IS NULL) FROM t_vk_open_answer AS r) = ARRAY[true], 'the open call of a revoked key answers one NULL';
  ASSERT pg_temp.t_vk_columns('t_vk_link_read_answer')
         = ARRAY['link_state text', 'api_key_id integer', 'link_expires_at bigint', 'shodan_sealed_hex text', 'abuseipdb_sealed_hex text'],
         'the link read call answers link_state text, api_key_id integer, link_expires_at bigint, shodan_sealed_hex text, abuseipdb_sealed_hex text';
  ASSERT (SELECT array_agg(r.link_state) FROM t_vk_link_read_answer AS r) = ARRAY['open'], 'the link read call answers one open row';
  ASSERT pg_temp.t_vk_columns('t_vk_apply_answer') = ARRAY['apply_status text'], 'the apply call answers one text column, apply_status';
  ASSERT (SELECT array_agg(r.apply_status) FROM t_vk_apply_answer AS r) = ARRAY['applied'], 'the apply call that changes nothing answers applied';
  ASSERT pg_temp.t_vk_rows(1) = 'abuseipdb=' || pg_temp.t_vk_sealed(1, 'abuseipdb') || ',shodan=' || pg_temp.t_vk_sealed(1, 'shodan'),
         'an apply with no text and no delete flag keeps both rows';
  ASSERT pg_temp.t_vk_columns('t_vk_purge_answer') = ARRAY['purged_key_count integer'], 'the purge call answers one integer column, purged_key_count';
  ASSERT (SELECT array_agg(r.purged_key_count) FROM t_vk_purge_answer AS r) = ARRAY[0], 'a purge with the limit 0 answers 0';
  ASSERT pg_temp.t_vk_columns('t_vk_link_purge_answer') = ARRAY['purged_link_count integer'],
         'the link purge call answers one integer column, purged_link_count';
  ASSERT (SELECT array_agg(r.purged_link_count) FROM t_vk_link_purge_answer AS r) = ARRAY[0], 'a link purge with the limit 0 answers 0';
  ASSERT NOT pg_temp.t_vk_has_link(9001), 'the open call of a revoked key writes no row';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_vk_read(pg_temp.t_vk_hash(1)) = pg_temp.t_vk_answer(1, true, true), 'an active key answers its id, its fingerprint and both of its texts';
  ASSERT pg_temp.t_vk_answer(1, true, true) LIKE '%|' || left(encode(sha256(convert_to(pg_temp.t_vk_hash(1), 'UTF8')), 'hex'), 32) || '|%',
         'the fingerprint is the first 32 hex digits of the SHA-256 of the key hash';
  ASSERT pg_temp.t_vk_read(pg_temp.t_vk_hash(2)) = pg_temp.t_vk_answer(2, true, true), 'the decoy key answers its own texts';
  ASSERT pg_temp.t_vk_read(pg_temp.t_vk_hash(3)) = 'null|null|null|null', 'a revoked key answers four NULLs, though it holds rows';
  ASSERT pg_temp.t_vk_read(pg_temp.t_vk_hash(4)) = 'null|null|null|null', 'an expired key answers four NULLs, though it holds rows';
  ASSERT pg_temp.t_vk_read(pg_temp.t_vk_hash(5)) = pg_temp.t_vk_answer(5, false, false), 'an active key with no row answers its id, its fingerprint and two NULLs';
  ASSERT pg_temp.t_vk_read(pg_temp.t_vk_hash(6)) = pg_temp.t_vk_answer(6, false, true), 'a key with only abuseipdb answers NULL for shodan';
  ASSERT pg_temp.t_vk_read(pg_temp.t_vk_hash(7)) = pg_temp.t_vk_answer(7, true, false), 'a key with only shodan answers NULL for abuseipdb';
  ASSERT pg_temp.t_vk_read(pg_temp.t_vk_hash(999)) = 'null|null|null|null', 'a hash with no row answers four NULLs on one row';
  ASSERT pg_temp.t_vk_read(NULL) = 'null|null|null|null', 'a NULL hash answers four NULLs on one row';
END
$$;

SELECT pg_temp.t_vk_key(10, true, NULL);
SELECT pg_temp.t_vk_key(11, true, NULL);
SELECT pg_temp.t_vk_store_link(110, 11, to_timestamp(1893456000));

CREATE FUNCTION pg_temp.t_vk_open_raises(p_api_key_id integer, p_link_hash text, p_lifetime_seconds integer) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  PERFORM api.fn_vendor_key_link_open(p_api_key_id, p_link_hash, p_lifetime_seconds);
  RETURN NULL;
EXCEPTION WHEN OTHERS THEN
  RETURN SQLSTATE;
END
$$;

DO $$
DECLARE
  before    text    := pg_temp.t_vk_snapshot();
  whole_now bigint  := floor(extract(epoch FROM now()))::bigint;
  key_10    integer := pg_temp.t_vk_id(10);
  first_end bigint;
BEGIN
  ASSERT pg_temp.t_vk_open_raises(key_10, pg_temp.t_vk_th(100), NULL) = 'P0001', 'a NULL lifetime raises';
  ASSERT pg_temp.t_vk_open_raises(key_10, pg_temp.t_vk_th(100), 0) = 'P0001', 'a lifetime of 0 raises';
  ASSERT pg_temp.t_vk_open_raises(key_10, pg_temp.t_vk_th(100), -1) = 'P0001', 'a negative lifetime raises';
  ASSERT pg_temp.t_vk_open_raises(pg_temp.t_vk_id(3), pg_temp.t_vk_th(100), 1) IS NULL, 'a lifetime of one second raises nothing';
  ASSERT api.fn_vendor_key_link_open(pg_temp.t_vk_id(3), pg_temp.t_vk_th(100), 900) IS NULL, 'a revoked key answers NULL';
  ASSERT api.fn_vendor_key_link_open(pg_temp.t_vk_id(4), pg_temp.t_vk_th(100), 900) IS NULL, 'an expired key answers NULL';
  ASSERT api.fn_vendor_key_link_open((SELECT max(ak.id) + 1000 FROM api_keys AS ak), pg_temp.t_vk_th(100), 900) IS NULL,
         'an id with no key row answers NULL';
  ASSERT api.fn_vendor_key_link_open(NULL, pg_temp.t_vk_th(100), 900) IS NULL, 'a NULL id answers NULL';
  ASSERT pg_temp.t_vk_snapshot() = before, 'a refused or inactive mint writes nothing';

  first_end := api.fn_vendor_key_link_open(key_10, pg_temp.t_vk_th(100), 900);
  ASSERT first_end = whole_now + 900, 'the mint answers the whole second of now() plus the lifetime';
  ASSERT pg_temp.t_vk_links(10) = pg_temp.t_vk_link_row(100, 10, whole_now + 900), 'the mint writes one row of its hash, the fingerprint of the key and the end';
  ASSERT (SELECT vkl.expires_at FROM vendor_key_link AS vkl WHERE vkl.link_hash = pg_temp.t_vk_th(100)) = now() + interval '900 seconds',
         'the stored end is now() plus the lifetime';
  ASSERT api.fn_vendor_key_link_open(key_10, pg_temp.t_vk_th(101), 60) = whole_now + 60, 'a second mint answers the end of its own lifetime';
  ASSERT pg_temp.t_vk_links(10) = pg_temp.t_vk_link_row(100, 10, whole_now + 900) || ',' || pg_temp.t_vk_link_row(101, 10, whole_now + 60),
         'a second mint writes a second row and keeps the first one';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(100)) = pg_temp.t_vk_open_answer(10, whole_now + 900, false, false), 'the first link is open';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(101)) = pg_temp.t_vk_open_answer(10, whole_now + 60, false, false), 'the second link is open too';

  before := pg_temp.t_vk_snapshot();
  ASSERT pg_temp.t_vk_open_raises(key_10, pg_temp.t_vk_th(100), 900) = '23505', 'a mint of a hash already stored raises a unique violation';
  ASSERT pg_temp.t_vk_open_raises(key_10, NULL, 900) = '23502', 'a mint of a NULL hash raises a not-null violation';
  ASSERT pg_temp.t_vk_open_raises(key_10, upper(pg_temp.t_vk_th(102)), 900) = '23514', 'a mint of an upper case hash raises a check violation';
  ASSERT pg_temp.t_vk_open_raises(key_10, left(pg_temp.t_vk_th(102), 63), 900) = '23514', 'a mint of a hash of 63 digits raises a check violation';
  ASSERT pg_temp.t_vk_snapshot() = before, 'a mint that raises writes nothing';
  ASSERT pg_temp.t_vk_links(11) = pg_temp.t_vk_link_row(110, 11, 1893456000), 'the mints of the key 10 keep the row of the key 11';
END
$$;

DO $$
DECLARE
  whole_now bigint := floor(extract(epoch FROM now()))::bigint;
BEGIN
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(1)) = pg_temp.t_vk_open_answer(1, 1893456000, true, true),
         'an open link answers its key, its end and both texts';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(2)) = pg_temp.t_vk_open_answer(2, 1893456000, true, true), 'the decoy link answers the texts of its own key';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(6)) = pg_temp.t_vk_open_answer(6, 1893456000, false, true), 'an open key with only abuseipdb answers NULL for shodan';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(7)) = pg_temp.t_vk_open_answer(7, 1893456000, true, false), 'an open key with only shodan answers NULL for abuseipdb';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(5)) = pg_temp.t_vk_open_answer(5, 1893456000, false, false), 'an open key with no vendor row answers two NULLs';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(16)) = pg_temp.t_vk_open_answer(1, whole_now + 1, true, true), 'a link that ends a second after now() is open';

  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(13)) = 'expired|null|null|null|null', 'a link that ended an hour ago is expired, with no text';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(15)) = 'expired|null|null|null|null', 'a link that ends at now() is expired';

  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(9001)) = 'invalid|null|null|null|null', 'a hash with no row is invalid, on one row';
  ASSERT pg_temp.t_vk_link_read(NULL) = 'invalid|null|null|null|null', 'a NULL hash is invalid, on one row';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(3)) = 'invalid|null|null|null|null', 'a link of a revoked key is invalid, though the key holds texts';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(4)) = 'invalid|null|null|null|null', 'a link of an expired key is invalid';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(14)) = 'invalid|null|null|null|null', 'a link with the fingerprint of another key is invalid';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(17)) = 'invalid|null|null|null|null', 'an ended link of a revoked key is invalid, not expired';
END
$$;

SELECT pg_temp.t_vk_key(8, true,  NULL);
SELECT pg_temp.t_vk_key(9, false, NULL);
SELECT pg_temp.t_vk_store(9, 'shodan');
SELECT pg_temp.t_vk_store_link(8,  8, to_timestamp(1893456000));
SELECT pg_temp.t_vk_store_link(80, 8, to_timestamp(1893456000));
INSERT INTO vendor_key_link (link_hash, api_key_id, key_fingerprint, expires_at)
  VALUES (pg_temp.t_vk_th(18), pg_temp.t_vk_id(9), pg_temp.t_vk_fpn(1), to_timestamp(1893456000));

CREATE FUNCTION pg_temp.t_vk_raises(p_api_key_id integer, p_link_hash text, p_key_fingerprint text, p_is_link_spent boolean,
                                    p_shodan_sealed_hex text, p_is_shodan_deleted boolean,
                                    p_abuseipdb_sealed_hex text, p_is_abuseipdb_deleted boolean) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
  PERFORM api.fn_vendor_key_apply(p_api_key_id, p_link_hash, p_key_fingerprint, p_is_link_spent, p_shodan_sealed_hex, p_is_shodan_deleted,
                                  p_abuseipdb_sealed_hex, p_is_abuseipdb_deleted);
  RETURN false;
EXCEPTION WHEN raise_exception THEN
  RETURN true;
END
$$;

DO $$
DECLARE
  before text := pg_temp.t_vk_snapshot();
  s8     text := pg_temp.t_vk_sealed(8, 'shodan');
  th8    text := pg_temp.t_vk_th(8);
BEGIN
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(9), NULL, pg_temp.t_vk_fpn(9), false, s8, false, NULL, true) = 'inactive', 'a revoked key answers inactive';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(4), NULL, pg_temp.t_vk_fpn(4), false, s8, false, NULL, true) = 'inactive', 'an expired key answers inactive';
  ASSERT api.fn_vendor_key_apply((SELECT max(ak.id) + 1000 FROM api_keys AS ak), NULL, NULL, false, s8, false, NULL, false) = 'inactive',
         'an id with no key row answers inactive';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(2), false, s8, false, NULL, false) = 'inactive',
         'an API-key apply with the fingerprint of another key answers inactive';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), NULL, NULL, false, s8, false, NULL, false) = 'inactive',
         'an API-key apply with a NULL fingerprint answers inactive';

  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), pg_temp.t_vk_th(9001), NULL, true, s8, false, NULL, false) = 'invalid',
         'a hash with no row answers invalid';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(1), th8, NULL, true, s8, false, NULL, false) = 'invalid',
         'a link of the key 8 sent with the id of the key 1 answers invalid';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(1), pg_temp.t_vk_th(18), NULL, true, NULL, true, NULL, false) = 'invalid',
         'a link of the key 9 that holds the fingerprint of the key 1 answers invalid for the key 1';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(3), pg_temp.t_vk_th(3), NULL, true, NULL, true, NULL, false) = 'invalid',
         'a link of a revoked key answers invalid';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(4), pg_temp.t_vk_th(4), NULL, true, NULL, true, NULL, false) = 'invalid',
         'a link of an expired key answers invalid';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(1), pg_temp.t_vk_th(14), NULL, true, NULL, true, NULL, false) = 'invalid',
         'a link with the fingerprint of another key answers invalid';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(3), pg_temp.t_vk_th(17), NULL, true, NULL, true, NULL, false) = 'invalid',
         'an ended link of a revoked key answers invalid, not expired';

  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(13), pg_temp.t_vk_th(13), NULL, true, NULL, true, NULL, false) = 'expired',
         'a link that ended an hour ago answers expired';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(1), pg_temp.t_vk_th(15), NULL, true, NULL, true, NULL, false) = 'expired',
         'a link that ends at now() answers expired';
  ASSERT pg_temp.t_vk_snapshot() = before, 'an inactive, invalid or expired apply writes no key, deletes no key and deletes no link row';

  ASSERT pg_temp.t_vk_raises(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), true, s8, false, NULL, false), 'a spend on the API-key way raises';
  ASSERT pg_temp.t_vk_raises(pg_temp.t_vk_id(8), th8, pg_temp.t_vk_fpn(8), false, s8, false, NULL, false), 'a link hash with a fingerprint raises';
  ASSERT pg_temp.t_vk_raises(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, s8, true, NULL, false), 'a shodan text with its delete flag raises';
  ASSERT pg_temp.t_vk_raises(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, NULL, false, pg_temp.t_vk_sealed(8, 'abuseipdb'), true),
         'an abuseipdb text with its delete flag raises';
  ASSERT pg_temp.t_vk_raises(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), NULL, s8, false, NULL, false), 'a NULL spend flag raises';
  ASSERT pg_temp.t_vk_raises(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, s8, NULL, NULL, false), 'a NULL shodan delete flag raises';
  ASSERT pg_temp.t_vk_raises(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, s8, false, NULL, NULL), 'a NULL abuseipdb delete flag raises';
  ASSERT NOT pg_temp.t_vk_raises(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, NULL, false, NULL, false), 'an API-key apply with valid arguments raises nothing';
  ASSERT NOT pg_temp.t_vk_raises(pg_temp.t_vk_id(8), th8, NULL, false, NULL, false, NULL, false), 'a link apply with valid arguments raises nothing';
  ASSERT pg_temp.t_vk_snapshot() = before, 'an apply that raises writes nothing';
END
$$;

DO $$
DECLARE
  key_1_rows text := pg_temp.t_vk_rows(1);
  links_8    text := pg_temp.t_vk_links(8);
  s8a        text := pg_temp.t_vk_sealed(8, 'shodan');
  s8b        text := pg_temp.t_vk_sealed(80, 'shodan');
  a8         text := pg_temp.t_vk_sealed(8, 'abuseipdb');
BEGIN
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, s8a, false, NULL, false) = 'applied', 'a shodan text answers applied';
  ASSERT pg_temp.t_vk_rows(8) = 'shodan=' || s8a, 'a shodan text inserts the shodan row only';
  ASSERT (SELECT vk.saved_at FROM vendor_key AS vk WHERE vk.api_key_id = pg_temp.t_vk_id(8) AND vk.vendor_name = 'shodan') = now(),
         'a new row is saved at now()';

  UPDATE vendor_key AS vk SET saved_at = now() - interval '1 day' WHERE vk.api_key_id = pg_temp.t_vk_id(8);
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, NULL, false, a8, false) = 'applied',
         'an abuseipdb text answers applied';
  ASSERT pg_temp.t_vk_rows(8) = 'abuseipdb=' || a8 || ',shodan=' || s8a, 'an abuseipdb text inserts its row and keeps the shodan row';
  ASSERT (SELECT vk.saved_at FROM vendor_key AS vk WHERE vk.api_key_id = pg_temp.t_vk_id(8) AND vk.vendor_name = 'shodan')
         = now() - interval '1 day',
         'a vendor with no text and no delete flag keeps its saved_at';

  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, s8b, false, NULL, false) = 'applied', 'a second shodan text answers applied';
  ASSERT pg_temp.t_vk_rows(8) = 'abuseipdb=' || a8 || ',shodan=' || s8b, 'a second shodan text replaces the shodan text only';
  ASSERT (SELECT vk.saved_at FROM vendor_key AS vk WHERE vk.api_key_id = pg_temp.t_vk_id(8) AND vk.vendor_name = 'shodan') = now(),
         'a replaced text is saved at now() again';

  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, NULL, true, NULL, false) = 'applied', 'a shodan delete answers applied';
  ASSERT pg_temp.t_vk_rows(8) = 'abuseipdb=' || a8, 'a shodan delete removes the shodan row only';
  ASSERT pg_temp.t_vk_rows(1) = key_1_rows, 'a delete keeps the rows of another key';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, NULL, true, NULL, false) = 'applied', 'a delete of a missing row answers applied';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, s8a, false, NULL, true) = 'applied', 'a shodan text with an abuseipdb delete answers applied';
  ASSERT pg_temp.t_vk_rows(8) = 'shodan=' || s8a, 'one call writes shodan and deletes abuseipdb';
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, NULL, false, NULL, false) = 'applied', 'an apply with nothing to do answers applied';
  ASSERT pg_temp.t_vk_rows(8) = 'shodan=' || s8a, 'an apply with nothing to do keeps the rows';
  ASSERT pg_temp.t_vk_rows(1) = key_1_rows, 'no apply of the key 8 touched the key 1';
  ASSERT pg_temp.t_vk_links(8) = links_8, 'an apply on the API-key way leaves the link rows as they are';
END
$$;

DO $$
DECLARE
  s8c    text := pg_temp.t_vk_sealed(81, 'shodan');
  a8c    text := pg_temp.t_vk_sealed(81, 'abuseipdb');
  before text;
BEGIN
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), pg_temp.t_vk_th(80), NULL, false, NULL, false, a8c, false) = 'applied',
         'a link apply that does not spend answers applied';
  ASSERT pg_temp.t_vk_rows(8) = 'abuseipdb=' || a8c || ',shodan=' || pg_temp.t_vk_sealed(8, 'shodan'), 'the link apply writes the abuseipdb text';
  ASSERT pg_temp.t_vk_has_link(80), 'a link apply that does not spend keeps the row of the link';

  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), pg_temp.t_vk_th(8), NULL, true, s8c, false, NULL, false) = 'applied', 'an open link answers applied';
  ASSERT pg_temp.t_vk_rows(8) = 'abuseipdb=' || a8c || ',shodan=' || s8c, 'the link apply writes the shodan text';
  ASSERT NOT pg_temp.t_vk_has_link(8), 'the spend deletes the row of the link';
  ASSERT pg_temp.t_vk_links(8) = pg_temp.t_vk_link_row(80, 8, 1893456000), 'the spend keeps the other link of the key';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(8)) = 'invalid|null|null|null|null', 'the spent link reads invalid';

  before := pg_temp.t_vk_snapshot();
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), pg_temp.t_vk_th(8), NULL, true, NULL, true, NULL, false) = 'invalid', 'the same link again answers invalid';
  ASSERT pg_temp.t_vk_snapshot() = before, 'the second use writes nothing';

  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), pg_temp.t_vk_th(80), NULL, true, NULL, false, NULL, true) = 'applied', 'the other link still answers applied';
  ASSERT pg_temp.t_vk_rows(8) = 'shodan=' || s8c, 'the other link deletes the abuseipdb row';
  ASSERT pg_temp.t_vk_links(8) = '', 'the second spend deletes the last link row of the key';
END
$$;

DO $$
DECLARE
  apply_body text := regexp_replace(pg_get_functiondef('api.fn_vendor_key_apply(integer, text, text, boolean, text, boolean, text, boolean)'::regprocedure),
                                    '--[^\n]*', '', 'g');
BEGIN
  ASSERT apply_body ~ 'FROM public\.api_keys AS ak\s+WHERE ak\.id = p_api_key_id\s+FOR UPDATE;', 'api.fn_vendor_key_apply locks the api_keys row of the key';
  ASSERT apply_body ~ 'FROM public\.vendor_key_link AS vkl\s+WHERE vkl\.link_hash = p_link_hash\s+FOR UPDATE;',
         'api.fn_vendor_key_apply locks the link row';
  ASSERT position('public.api_keys' IN apply_body) < position('public.vendor_key_link' IN apply_body),
         'api.fn_vendor_key_apply locks the api_keys row before the link row';
END
$$;

SELECT pg_temp.t_vk_key(30, true, NULL);
SELECT pg_temp.t_vk_store(30, 'shodan');
INSERT INTO billing_orders (provider, provider_order_ref, order_id, status, claimable_until, claimed_at, api_key_id)
  SELECT 'manual', 'vk-30', NULL, 'claimed', NULL, now() - interval '1 day', pg_temp.t_vk_id(30);
DO $$
DECLARE
  key_30    integer := pg_temp.t_vk_id(30);
  old_fp    text    := (SELECT r.key_fingerprint FROM api.fn_vendor_key_read(pg_temp.t_vk_hash(30)) AS r);
  link_end  bigint  := api.fn_vendor_key_link_open(pg_temp.t_vk_id(30), pg_temp.t_vk_th(300), 900);
  open_30   text    := 'open|' || pg_temp.t_vk_id(30) || '|' || link_end || '|' || pg_temp.t_vk_sealed(30, 'shodan') || '|null';
  new_hash  text;
  new_fp    text;
  before    text;
BEGIN
  ASSERT old_fp = pg_temp.t_vk_fpn(30), 'the read answers the fingerprint of the key 30';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(300)) = open_30, 'the new link is open before the regenerate';
  ASSERT (SELECT r.regenerate_status FROM api.fn_billing_regenerate_key('manual', 'vk-30') AS r) = 'regenerating', 'the regenerate answers regenerating';
  new_hash := (SELECT ak.key_hash FROM api_keys AS ak WHERE ak.id = key_30);
  ASSERT new_hash <> pg_temp.t_vk_hash(30), 'the regenerate wrote a new hash on the same row';

  before := pg_temp.t_vk_snapshot();
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(300)) = 'invalid|null|null|null|null', 'the link written before the regenerate is invalid';
  ASSERT api.fn_vendor_key_apply(key_30, pg_temp.t_vk_th(300), NULL, true, NULL, true, NULL, false) = 'invalid',
         'a link apply of the link written before the regenerate answers invalid';
  ASSERT api.fn_vendor_key_apply(key_30, NULL, old_fp, false, NULL, true, NULL, false) = 'inactive',
         'an API-key apply with the old fingerprint answers inactive';
  ASSERT pg_temp.t_vk_snapshot() = before, 'the applies with the old fingerprint write nothing';

  new_fp := (SELECT r.key_fingerprint FROM api.fn_vendor_key_read(new_hash) AS r);
  ASSERT new_fp = pg_temp.t_vk_fp(new_hash) AND new_fp <> old_fp, 'the read answers the fingerprint of the new hash';
  ASSERT api.fn_vendor_key_link_open(key_30, pg_temp.t_vk_th(301), 900) = link_end, 'a mint after the regenerate answers its end';
  ASSERT (SELECT vkl.key_fingerprint FROM vendor_key_link AS vkl WHERE vkl.link_hash = pg_temp.t_vk_th(301)) = new_fp,
         'the mint after the regenerate writes the new fingerprint';
  ASSERT pg_temp.t_vk_link_read(pg_temp.t_vk_th(301)) = open_30, 'the link written after the regenerate is open';
  ASSERT api.fn_vendor_key_apply(key_30, pg_temp.t_vk_th(301), NULL, true, NULL, true, NULL, false) = 'applied', 'its apply answers applied';
  ASSERT NOT EXISTS (SELECT 1 FROM vendor_key AS vk WHERE vk.api_key_id = key_30), 'the apply deleted the shodan row';
  ASSERT NOT pg_temp.t_vk_has_link(301), 'the apply spent the new link';
  ASSERT pg_temp.t_vk_has_link(300), 'the old link row stays until the purge';

  DELETE FROM billing_orders AS bo WHERE bo.provider = 'manual' AND bo.provider_order_ref = 'vk-30';
  DELETE FROM api_keys AS ak WHERE ak.id = key_30;
  ASSERT NOT pg_temp.t_vk_has_link(300), 'the delete of the key 30 deletes its old link row';
END
$$;

SELECT pg_temp.t_vk_key(20, true,  now() - interval '400 days');
SELECT pg_temp.t_vk_key(21, false, now() - interval '40 days');
SELECT pg_temp.t_vk_key(22, true,  now() - interval '40 days');
SELECT pg_temp.t_vk_key(23, true,  now() - interval '40 days');
SELECT pg_temp.t_vk_key(24, true,  now() - interval '30 days 1 second');
SELECT pg_temp.t_vk_key(25, true,  now() - interval '30 days' + interval '1 second');
SELECT pg_temp.t_vk_key(26, true,  now() - interval '30 days');
SELECT pg_temp.t_vk_key(27, true,  NULL);
UPDATE api_keys AS ak SET created_at = now() - interval '400 days' WHERE ak.key_hash = pg_temp.t_vk_hash(27);
SELECT pg_temp.t_vk_store(21, 'shodan'), pg_temp.t_vk_store(21, 'abuseipdb');
SELECT pg_temp.t_vk_store(22, 'shodan'), pg_temp.t_vk_store(23, 'abuseipdb'), pg_temp.t_vk_store(24, 'shodan');
SELECT pg_temp.t_vk_store(25, 'shodan'), pg_temp.t_vk_store(26, 'shodan'), pg_temp.t_vk_store(27, 'shodan');
SELECT pg_temp.t_vk_store_link(24, 24, to_timestamp(1893456000));

DO $$
DECLARE
  kept text := pg_temp.t_vk_rows(1) || pg_temp.t_vk_rows(2) || pg_temp.t_vk_rows(3) || pg_temp.t_vk_rows(4);
BEGIN
  ASSERT pg_temp.t_vk_id(20) < pg_temp.t_vk_id(21) AND pg_temp.t_vk_id(21) < pg_temp.t_vk_id(22)
         AND pg_temp.t_vk_id(22) < pg_temp.t_vk_id(23) AND pg_temp.t_vk_id(23) < pg_temp.t_vk_id(24),
         'the keys 20 to 24 have rising ids';
  ASSERT api.fn_vendor_key_purge(2) = 2, 'a purge with the limit 2 clears two keys, though the key 21 held two rows';
  ASSERT pg_temp.t_vk_rows(21) = '' AND pg_temp.t_vk_rows(22) = '', 'the purge clears the two lowest ids that hold rows';
  ASSERT pg_temp.t_vk_rows(23) <> '' AND pg_temp.t_vk_rows(24) <> '', 'the purge leaves the expired keys past its limit';
  ASSERT api.fn_vendor_key_purge(10) = 2, 'the next purge clears the keys 23 and 24';
  ASSERT pg_temp.t_vk_rows(23) = '' AND pg_temp.t_vk_rows(24) = '', 'a key 30 days and a second past its expiry is cleared';
  ASSERT pg_temp.t_vk_rows(25) <> '', 'a key 30 days less a second past its expiry keeps its row';
  ASSERT pg_temp.t_vk_rows(26) <> '', 'a key exactly 30 days past its expiry keeps its row';
  ASSERT pg_temp.t_vk_rows(27) <> '', 'a key that never expires keeps its row, however old it is';
  ASSERT pg_temp.t_vk_rows(1) || pg_temp.t_vk_rows(2) || pg_temp.t_vk_rows(3) || pg_temp.t_vk_rows(4) = kept,
         'a revoked key and a key expired a second ago keep their rows';
  ASSERT pg_temp.t_vk_id(21) IS NOT NULL, 'the purge keeps the api_keys row';
  ASSERT pg_temp.t_vk_links(24) = pg_temp.t_vk_link_row(24, 24, 1893456000), 'the purge keeps the link row of a cleared key';
  ASSERT api.fn_vendor_key_purge(10) = 0, 'a purge with nothing left answers 0';
  ASSERT api.fn_vendor_key_purge(NULL) IS NULL, 'a NULL limit answers NULL';
  ASSERT pg_temp.t_vk_rows(25) <> '', 'a NULL limit deletes nothing';
END
$$;

SELECT pg_temp.t_vk_key(40, true, NULL), pg_temp.t_vk_key(41, true, NULL), pg_temp.t_vk_key(42, true, NULL);
SELECT pg_temp.t_vk_key(43, true, NULL), pg_temp.t_vk_key(44, true, NULL);
SELECT pg_temp.t_vk_store_link(400, 40, now() - interval '1 second');
SELECT pg_temp.t_vk_store_link(410, 41, now() - interval '2 days');
SELECT pg_temp.t_vk_store_link(420, 42, now() - interval '3 days');
SELECT pg_temp.t_vk_store_link(430, 43, now());
SELECT pg_temp.t_vk_store_link(440, 44, now() + interval '1 second');
DO $$
DECLARE
  open_rows text := (SELECT string_agg(vkl.link_hash, ',' ORDER BY vkl.link_hash) FROM vendor_key_link AS vkl WHERE vkl.expires_at >= now());
BEGIN
  ASSERT (SELECT count(*) FROM vendor_key_link AS vkl WHERE vkl.expires_at < now()) = 5, 'five rows have ended before the purge';
  ASSERT api.fn_vendor_key_link_purge(2) = 2, 'a link purge with the limit 2 deletes two rows';
  ASSERT (SELECT count(*) FROM vendor_key_link AS vkl WHERE vkl.expires_at < now()) = 3, 'three ended rows are left';
  ASSERT api.fn_vendor_key_link_purge(10) = 3, 'the next link purge deletes the last three ended rows';
  ASSERT NOT (pg_temp.t_vk_has_link(13) OR pg_temp.t_vk_has_link(17) OR pg_temp.t_vk_has_link(400)
              OR pg_temp.t_vk_has_link(410) OR pg_temp.t_vk_has_link(420)),
         'the rows that ended are gone, the one that ended a second ago too';
  ASSERT pg_temp.t_vk_has_link(430), 'a row that ends at now() stays';
  ASSERT pg_temp.t_vk_has_link(440), 'a row that ends a second after now() stays';
  ASSERT pg_temp.t_vk_has_link(3), 'the open row of the revoked key 3 stays';
  ASSERT (SELECT string_agg(vkl.link_hash, ',' ORDER BY vkl.link_hash) FROM vendor_key_link AS vkl) = open_rows,
         'every row that has not ended stays';
  ASSERT pg_temp.t_vk_id(40) IS NOT NULL, 'the link purge keeps the api_keys row';
  ASSERT api.fn_vendor_key_link_purge(10) = 0, 'a link purge with nothing left answers 0';
  ASSERT api.fn_vendor_key_link_purge(NULL) IS NULL, 'a NULL limit answers NULL';
END
$$;

SELECT pg_temp.t_vk_key(45, true, NULL);
DO $$
DECLARE
  key_45 integer := pg_temp.t_vk_id(45);
BEGIN
  FOR i IN 1 .. 20 LOOP
    ASSERT api.fn_vendor_key_link_open(key_45, pg_temp.t_vk_th(4500 + i), 900) IS NOT NULL, 'each of 20 mints of one key answers its end';
  END LOOP;
  ASSERT (SELECT count(*) FROM vendor_key_link AS vkl WHERE vkl.api_key_id = key_45) = 20, '20 mints of one key leave 20 rows';
  UPDATE vendor_key_link AS vkl SET expires_at = now() - interval '1 hour' WHERE vkl.api_key_id = key_45;
  ASSERT api.fn_vendor_key_link_purge(100) = 20, 'the purge deletes the 20 ended rows';
  ASSERT pg_temp.t_vk_links(45) = '', 'the purge leaves the key no row';
END
$$;

DO $$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_vendor_key_read(text)'::regprocedure,                                                              's'::"char", false, ARRAY['search_path=pg_catalog'], true),
      ('api.fn_vendor_key_link_open(integer, text, integer)'::regprocedure,                                       'v'::"char", false, ARRAY['search_path=pg_catalog'], true),
      ('api.fn_vendor_key_link_read(text)'::regprocedure,                                                         's'::"char", false, ARRAY['search_path=pg_catalog'], true),
      ('api.fn_vendor_key_apply(integer, text, text, boolean, text, boolean, text, boolean)'::regprocedure,        'v'::"char", false, ARRAY['search_path=pg_catalog'], true),
      ('api.fn_vendor_key_purge(integer)'::regprocedure,                                                          'v'::"char", true,  ARRAY['search_path=pg_catalog'], true),
      ('api.fn_vendor_key_link_purge(integer)'::regprocedure,                                                     'v'::"char", true,  ARRAY['search_path=pg_catalog'], true),
      ('api.fn_vendor_key_fingerprint(text)'::regprocedure,                                                       's'::"char", true,  NULL::text[], false)) AS t (oid, volatility, is_strict, config, is_definer) LOOP
    ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_definer,
           f.oid::text || CASE WHEN f.is_definer THEN ' is SECURITY DEFINER' ELSE ' is SECURITY INVOKER' END;
    ASSERT (SELECT p.proconfig IS NOT DISTINCT FROM f.config FROM pg_proc AS p WHERE p.oid = f.oid), f.oid::text || ' has its search_path setting';
    ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f.oid) = f.volatility, f.oid::text || ' has its volatility';
    ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_strict, f.oid::text || ' is STRICT as listed';
  END LOOP;
  ASSERT NOT EXISTS (SELECT 1 FROM pg_proc AS p WHERE p.proname = 'fn_vendor_key_spent_edit_token_purge'), 'the old spent purge is gone';
  ASSERT to_regclass('public.vendor_key_spent_edit_token') IS NULL, 'the old spent table is gone';
  ASSERT NOT EXISTS (SELECT 1 FROM pg_proc AS p WHERE p.proname IN ('fn_vendor_key_edit_token_open', 'fn_vendor_key_edit_read', 'fn_vendor_key_edit_token_purge')),
         'the edit token functions are gone';
  ASSERT to_regclass('public.vendor_key_edit_token') IS NULL, 'the edit token table is gone';
END
$$;

DO $$
DECLARE
  bad_hex  text;
  bad_name text;
BEGIN
  INSERT INTO vendor_key (api_key_id, vendor_name, sealed_hex) VALUES (pg_temp.t_vk_id(5), 'shodan', repeat('0', 60));
  INSERT INTO vendor_key (api_key_id, vendor_name, sealed_hex) VALUES (pg_temp.t_vk_id(5), 'abuseipdb', repeat('f', 314));
  ASSERT pg_temp.t_vk_rows(5) = 'abuseipdb=' || repeat('f', 314) || ',shodan=' || repeat('0', 60), 'texts of 60 and 314 digits are taken';
  FOREACH bad_hex IN ARRAY ARRAY[repeat('0', 58), repeat('0', 316), repeat('0', 61), repeat('A', 60), repeat('g', 60)]
  LOOP
    BEGIN
      INSERT INTO vendor_key (api_key_id, vendor_name, sealed_hex) VALUES (pg_temp.t_vk_id(27), 'abuseipdb', bad_hex);
      RAISE EXCEPTION 'vendor_key took the sealed_hex %', bad_hex;
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;
  END LOOP;
  FOREACH bad_name IN ARRAY ARRAY['virustotal', 'Shodan', '']
  LOOP
    BEGIN
      INSERT INTO vendor_key (api_key_id, vendor_name, sealed_hex) VALUES (pg_temp.t_vk_id(27), bad_name, repeat('0', 60));
      RAISE EXCEPTION 'vendor_key took the vendor_name %', bad_name;
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;
  END LOOP;
END
$$;

DO $$
DECLARE
  bad_text text;
  key_5    integer := pg_temp.t_vk_id(5);
  fp5      text    := pg_temp.t_vk_fpn(5);
BEGIN
  INSERT INTO vendor_key_link (link_hash, api_key_id, key_fingerprint, expires_at) VALUES (repeat('f', 64), key_5, fp5, to_timestamp(1893456000));
  ASSERT pg_temp.t_vk_links(5) = pg_temp.t_vk_link_row(5, 5, 1893456000) || ',' || repeat('f', 64) || '|' || fp5 || '|1893456000',
         'a hash of 64 digits is taken';
  FOREACH bad_text IN ARRAY ARRAY[upper(pg_temp.t_vk_th(500)), 'g' || right(pg_temp.t_vk_th(500), 63), left(pg_temp.t_vk_th(500), 63), pg_temp.t_vk_th(500) || '0']
  LOOP
    BEGIN
      INSERT INTO vendor_key_link (link_hash, api_key_id, key_fingerprint, expires_at) VALUES (bad_text, key_5, fp5, now());
      RAISE EXCEPTION 'vendor_key_link took the link_hash %', bad_text;
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;
  END LOOP;
  FOREACH bad_text IN ARRAY ARRAY[upper(fp5), 'g' || right(fp5, 31), left(fp5, 31), fp5 || '0']
  LOOP
    BEGIN
      INSERT INTO vendor_key_link (link_hash, api_key_id, key_fingerprint, expires_at) VALUES (pg_temp.t_vk_th(500), key_5, bad_text, now());
      RAISE EXCEPTION 'vendor_key_link took the key_fingerprint %', bad_text;
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;
  END LOOP;
  BEGIN
    INSERT INTO vendor_key_link (link_hash, api_key_id, key_fingerprint, expires_at) VALUES (pg_temp.t_vk_th(5), key_5, fp5, now());
    RAISE EXCEPTION 'a second row of one hash was taken';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;
  BEGIN
    INSERT INTO vendor_key_link (link_hash, api_key_id, key_fingerprint, expires_at)
      VALUES (pg_temp.t_vk_th(500), (SELECT max(ak.id) + 1000 FROM api_keys AS ak), fp5, now());
    RAISE EXCEPTION 'a row of an id with no key row was taken';
  EXCEPTION WHEN foreign_key_violation THEN
    NULL;
  END;
  BEGIN
    INSERT INTO vendor_key_link (link_hash, key_fingerprint, expires_at) VALUES (pg_temp.t_vk_th(500), fp5, now());
    RAISE EXCEPTION 'a row with no api_key_id was taken';
  EXCEPTION WHEN not_null_violation THEN
    NULL;
  END;
  BEGIN
    INSERT INTO vendor_key_link (link_hash, api_key_id, expires_at) VALUES (pg_temp.t_vk_th(500), key_5, now());
    RAISE EXCEPTION 'a row with no key_fingerprint was taken';
  EXCEPTION WHEN not_null_violation THEN
    NULL;
  END;
  BEGIN
    INSERT INTO vendor_key_link (link_hash, api_key_id, key_fingerprint) VALUES (pg_temp.t_vk_th(500), key_5, fp5);
    RAISE EXCEPTION 'a row with no expires_at was taken';
  EXCEPTION WHEN not_null_violation THEN
    NULL;
  END;
END
$$;

DO $$
DECLARE
  s8 text := pg_temp.t_vk_sealed(8, 'shodan');
BEGIN
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, s8, false, NULL, false) = 'applied', 'the first save of the text';
  UPDATE vendor_key AS vk SET saved_at = now() - interval '1 day' WHERE vk.api_key_id = pg_temp.t_vk_id(8);
  ASSERT api.fn_vendor_key_apply(pg_temp.t_vk_id(8), NULL, pg_temp.t_vk_fpn(8), false, s8, false, NULL, false) = 'applied', 'the same text again';
  ASSERT (SELECT vk.saved_at FROM vendor_key AS vk WHERE vk.api_key_id = pg_temp.t_vk_id(8)) = now(), 'a save of the same text refreshes saved_at';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_vk_rows(2) || ';' || pg_temp.t_vk_links(2) = (SELECT d.decoy_state FROM t_vk_decoy AS d),
         'the vendor rows and the link row of the decoy key 2 never changed';
END
$$;

DO $$
DECLARE
  key_1_id integer := pg_temp.t_vk_id(1);
BEGIN
  ASSERT pg_temp.t_vk_rows(1) <> '' AND (SELECT count(*) FROM vendor_key_link AS vkl WHERE vkl.api_key_id = key_1_id) = 4,
         'the key 1 holds rows and four links before the delete';
  DELETE FROM api_keys AS ak WHERE ak.id = key_1_id;
  ASSERT NOT EXISTS (SELECT 1 FROM vendor_key AS vk WHERE vk.api_key_id = key_1_id), 'the delete of a key deletes its vendor rows';
  ASSERT NOT EXISTS (SELECT 1 FROM vendor_key_link AS vkl WHERE vkl.api_key_id = key_1_id), 'the delete of a key deletes its link rows';
  ASSERT pg_temp.t_vk_rows(2) <> '' AND pg_temp.t_vk_links(2) <> '', 'the delete keeps the rows and the link of another key';
END
$$;
