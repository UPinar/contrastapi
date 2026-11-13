CREATE TEMP VIEW t_email_disposable_domain_call AS SELECT * FROM api.fn_email_disposable_domain('mailinator.com');

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_email_disposable_domain_call'::regclass AND attnum > 0)
         = ARRAY['disposable_feed_loaded boolean', 'listed_domain text'],
         'api.fn_email_disposable_domain answers disposable_feed_loaded boolean and listed_domain text, in this order';
  ASSERT (SELECT indexdef FROM pg_indexes WHERE indexname = 'email_disposable_domain_pkey')
         = 'CREATE UNIQUE INDEX email_disposable_domain_pkey ON public.email_disposable_domain USING btree (domain)',
         'the primary key of email_disposable_domain is the index the candidates are looked up in';
  ASSERT (SELECT array_agg(row(c.*)::text) FROM t_email_disposable_domain_call AS c) = ARRAY[row(false, NULL)::text],
         'with an empty table, a domain answers one row: the feed is not loaded and no domain is listed';
END
$$;

INSERT INTO email_disposable_domain (domain) VALUES
  ('mailinator.com'), ('x.com'), ('a.x.com'), ('a.com'), ('z.a.com'), ('com');

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(q.domain, c.disposable_feed_loaded, c.listed_domain)::text ORDER BY q.position)
            FROM unnest(ARRAY['mailinator.com', 'a.b.mailinator.com', 'x.com', 'b.a.x.com', 'q.z.a.com',
                              'example.com', 'com', 'mailinator.com.evil.net', 'notmailinator.com', 'mailinator',
                              'A.B.MAILINATOR.COM', 'Z.A.Com', ''])
                 WITH ORDINALITY AS q (domain, position),
                 LATERAL (SELECT * FROM api.fn_email_disposable_domain(q.domain)) AS c)
         = ARRAY[row('mailinator.com', true, 'mailinator.com')::text,
                 row('a.b.mailinator.com', true, 'mailinator.com')::text,
                 row('x.com', true, 'x.com')::text,
                 row('b.a.x.com', true, 'a.x.com')::text,
                 row('q.z.a.com', true, 'z.a.com')::text,
                 row('example.com', true, NULL)::text,
                 row('com', true, NULL)::text,
                 row('mailinator.com.evil.net', true, NULL)::text,
                 row('notmailinator.com', true, NULL)::text,
                 row('mailinator', true, NULL)::text,
                 row('A.B.MAILINATOR.COM', true, 'mailinator.com')::text,
                 row('Z.A.Com', true, 'z.a.com')::text,
                 row('', true, NULL)::text],
         'each domain answers one row: the longest listed name among the domain and its parents, never the last label alone';
  ASSERT (SELECT count(*) FROM api.fn_email_disposable_domain('b.a.x.com')) = 1,
         'a domain under two listed names answers one row';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_email_disposable_domain(NULL)), 'api.fn_email_disposable_domain is STRICT';
  ASSERT (SELECT p.prosecdef AND p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p
           WHERE p.oid = 'api.fn_email_disposable_domain(text)'::regprocedure),
         'api.fn_email_disposable_domain is SECURITY DEFINER, STRICT, STABLE and sets search_path to pg_catalog';
END
$$;

DELETE FROM email_disposable_domain;
