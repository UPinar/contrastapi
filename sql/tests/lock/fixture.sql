\set ON_ERROR_STOP on
INSERT INTO cves (cve_id) VALUES ('CVE-2020-0001'), ('CVE-2020-0002'), ('CVE-2020-0003') ON CONFLICT DO NOTHING;
TRUNCATE api_keys, domain_watch, domain_change_event, cve_change_event RESTART IDENTITY CASCADE;
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
UPDATE change_event_purge_state SET max_purged_event_id = 0, max_unwatched_event_id = 0 WHERE event_table_name = 'domain_change_event';
INSERT INTO api_keys (key_hash) VALUES (repeat('a', 64)), (repeat('b', 64));

\if :is_cve
SELECT count(*) AS edit_row_count
  FROM (VALUES ('a', 'CVE-2020-0001'), ('a', 'CVE-2020-0002'), ('b', 'CVE-2020-0003')) AS item (key_label, cve_id)
  CROSS JOIN LATERAL api.fn_watchlist_edit_cve_lookup(repeat(item.key_label, 64), 'add', item.cve_id, 100) AS x;
INSERT INTO cve_change_event (cve_id, event_type, changed_at)
SELECT e.cve_id, 'kev_added', e.changed_at
  FROM (VALUES (CASE WHEN :{?b_first} THEN 2 ELSE 1 END, 'CVE-2020-0002', now() - interval '100 days'),
               (CASE WHEN :{?b_first} THEN 1 ELSE 2 END, 'CVE-2020-0003', now() - interval '100 days'),
               (3, 'CVE-2020-0001', now() - interval '100 days'),
               (4, CASE WHEN :{?b_last} THEN 'CVE-2020-0003' ELSE 'CVE-2020-0002' END, now() - interval '100 days'),
               (5, 'CVE-2020-0001', now())) AS e (ordinal, cve_id, changed_at)
 ORDER BY e.ordinal;
\else
SELECT count(*) AS edit_row_count
  FROM (VALUES ('a', 'x.example.com'), ('a', 'y.example.com'), ('b', 'w.example.org')) AS item (key_label, domain_name)
  CROSS JOIN LATERAL api.fn_watchlist_edit_dns_lookup(repeat(item.key_label, 64), 'add', item.domain_name,
                                                      substring(item.domain_name FROM '[^.]+\.[^.]+$'), 100, 20) AS x;
INSERT INTO domain_change_event (domain_name, event_type, changed_at, previous_value, current_value)
SELECT e.domain_name, 'ns_changed', e.changed_at, 'p', 'c'
  FROM (VALUES (CASE WHEN :{?b_first} THEN 2 ELSE 1 END, 'y.example.com', now() - interval '100 days'),
               (CASE WHEN :{?b_first} THEN 1 ELSE 2 END, 'w.example.org', now() - interval '100 days'),
               (3, 'x.example.com', now() - interval '100 days'),
               (4, CASE WHEN :{?b_last} THEN 'w.example.org' ELSE 'y.example.com' END, now() - interval '100 days'),
               (5, 'x.example.com', now())) AS e (ordinal, domain_name, changed_at)
 ORDER BY e.ordinal;
\endif

INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id, key_event_id)
SELECT heard.api_key_id, heard.item_id, heard.event_id,
       CASE WHEN NOT :is_cve AND (heard.is_young OR (:{?a_pending} AND heard.api_key_id = key_a.id)) THEN NULL
            ELSE row_number() OVER (PARTITION BY heard.api_key_id ORDER BY heard.event_id)
       END
  FROM (SELECT wic.api_key_id, wic.item_id, cce.event_id, cce.changed_at > now() - interval '90 days' AS is_young
          FROM watchlist_item_cve AS wic JOIN cve_change_event AS cce ON cce.cve_id = wic.cve_id
        UNION ALL
        SELECT wid.api_key_id, wid.item_id, dce.event_id, dce.changed_at > now() - interval '90 days' AS is_young
          FROM watchlist_item_domain AS wid JOIN domain_change_event AS dce ON dce.domain_name = wid.domain_name) AS heard
 CROSS JOIN (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('a', 64)) AS key_a
 ORDER BY heard.event_id;

UPDATE watchlist_key_state AS wks
   SET last_key_event_id = (SELECT coalesce(max(wer.key_event_id), 0) FROM watchlist_event_ref AS wer WHERE wer.api_key_id = wks.api_key_id),
       last_cve_event_id = (SELECT coalesce(max(cce.event_id), 0) FROM cve_change_event AS cce);
UPDATE watchlist_event_cursor AS wec
   SET previous_cursor = wks.last_key_event_id, delivered_cursor = wks.last_key_event_id
  FROM watchlist_key_state AS wks
 WHERE wks.api_key_id = wec.api_key_id;

SELECT wer.api_key_id, wer.item_id, wer.event_id, wer.key_event_id FROM watchlist_event_ref AS wer;
