CREATE FUNCTION pg_temp.t_x402_hash(p_label text) RETURNS text
  LANGUAGE sql IMMUTABLE
  RETURN lpad(p_label, 64, '0');

PREPARE t_x402_reserve_query AS SELECT * FROM api.fn_x402_payment_reserve($1, $2);
CREATE TEMP TABLE t_x402_reserve_answer AS EXECUTE t_x402_reserve_query(pg_temp.t_x402_hash('a0'), pg_temp.t_x402_hash('f0'));
DEALLOCATE t_x402_reserve_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_x402_reserve_answer'::regclass AND attnum > 0)
         = ARRAY['reserve_answer text', 'signature text'],
         'the reserve query answers reserve_answer and signature, in that order';
  ASSERT (SELECT array_agg(row(reserve_answer, signature)::text) FROM t_x402_reserve_answer) = ARRAY[row('reserved', NULL)::text],
         'the reserve query answers one row, reserved with no signature, for a new message';
  ASSERT (SELECT row(source_hash, status, signature, reserved_at = now())::text FROM x402_payment
           WHERE message_hash = pg_temp.t_x402_hash('a0'))
         = row(pg_temp.t_x402_hash('f0'), 'reserved', NULL, true)::text,
         'the reserve query writes a reserved row of its source, reserved now';
END
$$;

DO $$
DECLARE
  answer    record;
  sent_signature text := repeat('5', 87) || 'Q';
BEGIN
  SELECT * INTO answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('a1'), pg_temp.t_x402_hash('f1'));
  ASSERT row(answer.reserve_answer, answer.signature)::text = row('reserved', NULL)::text, 'a new message is reserved';
  SELECT * INTO answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('a1'), pg_temp.t_x402_hash('f1'));
  ASSERT row(answer.reserve_answer, answer.signature)::text = row('in_flight', NULL)::text,
         'a second reserve of a reserved message answers in_flight';
  ASSERT (SELECT count(*) FROM x402_payment WHERE message_hash = pg_temp.t_x402_hash('a1')) = 1,
         'the second reserve writes no second row';
  ASSERT api.fn_x402_payment_mark_settled(pg_temp.t_x402_hash('a1')), 'a reserved message is marked settled';
  SELECT * INTO answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('a1'), pg_temp.t_x402_hash('f1'));
  ASSERT row(answer.reserve_answer, answer.signature)::text = row('settled', NULL)::text,
         'a reserve of a settled message answers settled with no signature';

  PERFORM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('a2'), pg_temp.t_x402_hash('f2'));
  ASSERT api.fn_x402_payment_mark_pending(pg_temp.t_x402_hash('a2'), sent_signature), 'a reserved message is marked pending with a signature';
  SELECT * INTO answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('a2'), pg_temp.t_x402_hash('f2'));
  ASSERT row(answer.reserve_answer, answer.signature)::text = row('pending', sent_signature)::text,
         'a reserve of a pending message answers pending and the signature of the row';

  PERFORM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('a3'), pg_temp.t_x402_hash('f3'));
  ASSERT api.fn_x402_payment_mark_pending(pg_temp.t_x402_hash('a3'), NULL), 'a reserved message is marked pending with no signature';
  SELECT * INTO answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('a3'), pg_temp.t_x402_hash('f3'));
  ASSERT row(answer.reserve_answer, answer.signature)::text = row('pending', NULL)::text,
         'a reserve of a pending message with no signature answers pending and NULL';

  INSERT INTO x402_payment (message_hash, source_hash, status, reserved_at)
  VALUES (pg_temp.t_x402_hash('a4'), pg_temp.t_x402_hash('f4'), 'reserved', now() - interval '10 minutes');
  ASSERT api.fn_x402_payment_release(pg_temp.t_x402_hash('a4')), 'a reserved message is released';
  SELECT * INTO answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('a4'), pg_temp.t_x402_hash('f4'));
  ASSERT row(answer.reserve_answer, answer.signature)::text = row('reserved', NULL)::text,
         'a released message whose source is free is reserved again';
  ASSERT (SELECT row(status, reserved_at = now())::text FROM x402_payment WHERE message_hash = pg_temp.t_x402_hash('a4'))
         = row('reserved', true)::text,
         'the reserve of a released row sets reserved_at to now()';

  ASSERT (SELECT array_agg(row(right(message_hash, 2), right(source_hash, 2), status, signature)::text ORDER BY message_hash)
            FROM x402_payment)
         = ARRAY[row('a0', 'f0', 'reserved', NULL)::text, row('a1', 'f1', 'settled', NULL)::text,
                 row('a2', 'f2', 'pending', sent_signature)::text, row('a3', 'f3', 'pending', NULL)::text,
                 row('a4', 'f4', 'reserved', NULL)::text],
         'each call wrote only the row of its own message';
END
$$;

INSERT INTO x402_payment (message_hash, source_hash, status, reserved_at, signature) VALUES
  (pg_temp.t_x402_hash('b10'), pg_temp.t_x402_hash('f10'), 'reserved', now() - interval '149 seconds', NULL),
  (pg_temp.t_x402_hash('b11'), pg_temp.t_x402_hash('f11'), 'reserved', now() - interval '150 seconds', NULL),
  (pg_temp.t_x402_hash('b12'), pg_temp.t_x402_hash('f12'), 'reserved', now() - interval '151 seconds', NULL),
  (pg_temp.t_x402_hash('b13'), pg_temp.t_x402_hash('f13'), 'pending',  now() - interval '149 seconds', repeat('5', 88)),
  (pg_temp.t_x402_hash('b14'), pg_temp.t_x402_hash('f14'), 'pending',  now() - interval '149 seconds', NULL),
  (pg_temp.t_x402_hash('b15'), pg_temp.t_x402_hash('f15'), 'pending',  now() - interval '151 seconds', repeat('5', 88)),
  (pg_temp.t_x402_hash('b16'), pg_temp.t_x402_hash('f16'), 'settled',  now(),                          NULL),
  (pg_temp.t_x402_hash('b17'), pg_temp.t_x402_hash('f17'), 'released', now(),                          NULL);

DO $$
BEGIN
  ASSERT (SELECT row(reserve_answer, signature)::text FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('c10'), pg_temp.t_x402_hash('f10')))
         = row('source_busy', NULL)::text,
         'another message of a source reserved 149 seconds ago answers source_busy';
  ASSERT (SELECT count(*) FROM x402_payment WHERE message_hash = pg_temp.t_x402_hash('c10')) = 0,
         'a reserve that answers source_busy writes no row';
  ASSERT (SELECT reserve_answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('c11'), pg_temp.t_x402_hash('f11'))) = 'reserved',
         'a source reserved 150 seconds ago is free';
  ASSERT (SELECT reserve_answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('c12'), pg_temp.t_x402_hash('f12'))) = 'reserved',
         'a source reserved 151 seconds ago is free';
  ASSERT (SELECT reserve_answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('c13'), pg_temp.t_x402_hash('f13'))) = 'source_busy',
         'a pending row with a signature, reserved 149 seconds ago, keeps its source busy';
  ASSERT (SELECT reserve_answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('c14'), pg_temp.t_x402_hash('f14'))) = 'source_busy',
         'a pending row with no signature, reserved 149 seconds ago, keeps its source busy';
  ASSERT (SELECT reserve_answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('c15'), pg_temp.t_x402_hash('f15'))) = 'reserved',
         'a pending row reserved 151 seconds ago keeps its source no longer';
  ASSERT (SELECT reserve_answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('c16'), pg_temp.t_x402_hash('f16'))) = 'reserved',
         'a settled row reserved now keeps no source';
  ASSERT (SELECT reserve_answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('c17'), pg_temp.t_x402_hash('f17'))) = 'reserved',
         'a released row reserved now keeps no source';
  ASSERT (SELECT reserve_answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('c18'), pg_temp.t_x402_hash('f18'))) = 'reserved',
         'a source with no row is free while other sources are busy';
  ASSERT (SELECT reserve_answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('c19'), pg_temp.t_x402_hash('f18'))) = 'source_busy',
         'the message just reserved keeps its source busy for the next message';
  ASSERT (SELECT reserve_answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('c10'), pg_temp.t_x402_hash('f10'))) = 'source_busy',
         'a message refused as source_busy is refused again while the source stays busy';
  ASSERT (SELECT array_agg(right(message_hash, 3) || '=' || status ORDER BY message_hash) FROM x402_payment
           WHERE message_hash IN (SELECT pg_temp.t_x402_hash('b1' || n) FROM generate_series(0, 7) AS n))
         = ARRAY['b10=reserved', 'b11=reserved', 'b12=reserved', 'b13=pending', 'b14=pending', 'b15=pending', 'b16=settled', 'b17=released'],
         'a reserve of another message leaves the status of each row of its source as it was';
END
$$;

INSERT INTO x402_payment (message_hash, source_hash, status, reserved_at) VALUES
  (pg_temp.t_x402_hash('d1'), pg_temp.t_x402_hash('f20'), 'released', now() - interval '10 minutes'),
  (pg_temp.t_x402_hash('d2'), pg_temp.t_x402_hash('f20'), 'reserved', now()),
  (pg_temp.t_x402_hash('d3'), pg_temp.t_x402_hash('f21'), 'released', now() - interval '10 minutes'),
  (pg_temp.t_x402_hash('d4'), pg_temp.t_x402_hash('f21'), 'reserved', now() - interval '151 seconds');

DO $$
BEGIN
  ASSERT (SELECT row(reserve_answer, signature)::text FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('d1'), pg_temp.t_x402_hash('f20')))
         = row('source_busy', NULL)::text,
         'a released row whose source is busy answers source_busy';
  ASSERT (SELECT row(status, reserved_at = now() - interval '10 minutes')::text FROM x402_payment WHERE message_hash = pg_temp.t_x402_hash('d1'))
         = row('released', true)::text,
         'the refused reserve leaves the released row and its reserved_at as they were';
  ASSERT (SELECT reserve_answer FROM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('d3'), pg_temp.t_x402_hash('f21'))) = 'reserved',
         'a released row whose source was last reserved 151 seconds ago is reserved again';
  ASSERT (SELECT row(status, reserved_at = now())::text FROM x402_payment WHERE message_hash = pg_temp.t_x402_hash('d3'))
         = row('reserved', true)::text,
         'the released row is reserved again from now()';
END
$$;

DO $$
DECLARE
  mark_function  text;
  from_status    text;
  row_label      text;
  answer         boolean;
  old_signature  text;
  sent_signature text := repeat('5', 87) || 'Q';
  is_changed     boolean;
  to_status      text;
  found_row      text;
  expected_row   text;
  rows_before    text;
BEGIN
  FOREACH mark_function IN ARRAY ARRAY['mark_settled', 'mark_pending', 'release'] LOOP
    FOREACH from_status IN ARRAY ARRAY['reserved', 'pending_signed', 'pending_unsigned', 'settled', 'released', 'missing'] LOOP
      row_label := 'e' || left(md5(mark_function || from_status), 8);
      old_signature := CASE from_status WHEN 'pending_signed' THEN repeat('7', 88) END;
      IF from_status <> 'missing' THEN
        INSERT INTO x402_payment (message_hash, source_hash, status, signature, reserved_at)
        VALUES (pg_temp.t_x402_hash(row_label), pg_temp.t_x402_hash('f30'), split_part(from_status, '_', 1), old_signature,
                now() - interval '5 minutes');
      END IF;
      SELECT string_agg(row(message_hash, status, signature, reserved_at)::text, ',' ORDER BY message_hash) INTO rows_before
        FROM x402_payment WHERE message_hash <> pg_temp.t_x402_hash(row_label);

      IF mark_function = 'mark_settled' THEN
        answer := api.fn_x402_payment_mark_settled(pg_temp.t_x402_hash(row_label));
      ELSIF mark_function = 'mark_pending' THEN
        answer := api.fn_x402_payment_mark_pending(pg_temp.t_x402_hash(row_label), sent_signature);
      ELSE
        answer := api.fn_x402_payment_release(pg_temp.t_x402_hash(row_label));
      END IF;

      is_changed := CASE mark_function WHEN 'mark_pending' THEN from_status = 'reserved'
                                       ELSE from_status IN ('reserved', 'pending_signed', 'pending_unsigned') END;
      to_status := CASE mark_function WHEN 'mark_settled' THEN 'settled' WHEN 'mark_pending' THEN 'pending' ELSE 'released' END;
      ASSERT answer = is_changed, mark_function || ' from ' || from_status || ' answers ' || is_changed;

      SELECT row(status, signature, reserved_at = now() - interval '5 minutes')::text INTO found_row
        FROM x402_payment WHERE message_hash = pg_temp.t_x402_hash(row_label);
      expected_row := CASE WHEN from_status = 'missing' THEN NULL
                           WHEN is_changed THEN row(to_status, CASE WHEN to_status = 'pending' THEN sent_signature END, true)::text
                           ELSE row(split_part(from_status, '_', 1), old_signature, true)::text END;
      ASSERT found_row IS NOT DISTINCT FROM expected_row,
             mark_function || ' from ' || from_status || ' leaves the row ' || coalesce(expected_row, 'missing') || ', not ' || coalesce(found_row, 'missing');
      ASSERT (SELECT string_agg(row(message_hash, status, signature, reserved_at)::text, ',' ORDER BY message_hash)
                FROM x402_payment WHERE message_hash <> pg_temp.t_x402_hash(row_label)) = rows_before,
             mark_function || ' from ' || from_status || ' changes no other row';
    END LOOP;
  END LOOP;

  INSERT INTO x402_payment (message_hash, source_hash, status) VALUES (pg_temp.t_x402_hash('e1'), pg_temp.t_x402_hash('f31'), 'reserved');
  ASSERT api.fn_x402_payment_mark_pending(pg_temp.t_x402_hash('e1'), sent_signature), 'e1 is marked pending with a signature';
  ASSERT NOT api.fn_x402_payment_mark_pending(pg_temp.t_x402_hash('e1'), repeat('6', 88)), 'a pending row is not marked pending again';
  ASSERT (SELECT signature FROM x402_payment WHERE message_hash = pg_temp.t_x402_hash('e1')) = sent_signature,
         'a second mark_pending keeps the first signature';
  ASSERT api.fn_x402_payment_mark_settled(pg_temp.t_x402_hash('e1')), 'the pending row is marked settled';
  ASSERT (SELECT row(status, signature)::text FROM x402_payment WHERE message_hash = pg_temp.t_x402_hash('e1')) = row('settled', NULL)::text,
         'a row that leaves pending for settled loses its signature';
  ASSERT NOT api.fn_x402_payment_mark_settled(pg_temp.t_x402_hash('e1')), 'a settled row is not marked settled again';
  ASSERT NOT api.fn_x402_payment_mark_settled(NULL), 'mark_settled of a NULL hash answers false';
  ASSERT NOT api.fn_x402_payment_mark_pending(NULL, NULL), 'mark_pending of a NULL hash answers false';
  ASSERT NOT api.fn_x402_payment_release(NULL), 'release of a NULL hash answers false';
END
$$;

DO $$
DECLARE
  refused_by text;
  bad        record;
BEGIN
  FOR bad IN
    SELECT * FROM (VALUES
      (upper(pg_temp.t_x402_hash('ab1')), pg_temp.t_x402_hash('f40'), 'reserved', NULL, 'x402_payment_message_hash_format', 'an upper case message hash'),
      (repeat('a', 63),                   pg_temp.t_x402_hash('f40'), 'reserved', NULL, 'x402_payment_message_hash_format', 'a message hash of 63 digits'),
      (repeat('a', 65),                   pg_temp.t_x402_hash('f40'), 'reserved', NULL, 'x402_payment_message_hash_format', 'a message hash of 65 digits'),
      (repeat('g', 64),                   pg_temp.t_x402_hash('f40'), 'reserved', NULL, 'x402_payment_message_hash_format', 'a message hash with g'),
      (pg_temp.t_x402_hash('ab2'), upper(repeat('f', 64)),            'reserved', NULL, 'x402_payment_source_hash_format',  'an upper case source hash'),
      (pg_temp.t_x402_hash('ab2'), repeat('f', 63),                   'reserved', NULL, 'x402_payment_source_hash_format',  'a source hash of 63 digits'),
      (pg_temp.t_x402_hash('ab2'), repeat('f', 63) || ' ',            'reserved', NULL, 'x402_payment_source_hash_format',  'a source hash with a space'),
      (pg_temp.t_x402_hash('ab3'), pg_temp.t_x402_hash('f40'), 'done',     NULL,              'x402_payment_status_known',        'the status done'),
      (pg_temp.t_x402_hash('ab3'), pg_temp.t_x402_hash('f40'), 'Pending',  NULL,              'x402_payment_status_known',        'the status Pending'),
      (pg_temp.t_x402_hash('ab4'), pg_temp.t_x402_hash('f40'), 'reserved', repeat('5', 88),   'x402_payment_signature_only_pending', 'a signature on a reserved row'),
      (pg_temp.t_x402_hash('ab4'), pg_temp.t_x402_hash('f40'), 'settled',  repeat('5', 88),   'x402_payment_signature_only_pending', 'a signature on a settled row'),
      (pg_temp.t_x402_hash('ab4'), pg_temp.t_x402_hash('f40'), 'released', repeat('5', 88),   'x402_payment_signature_only_pending', 'a signature on a released row'),
      (pg_temp.t_x402_hash('ab5'), pg_temp.t_x402_hash('f40'), 'pending',  repeat('5', 63),   'x402_payment_signature_format',    'a signature of 63 digits'),
      (pg_temp.t_x402_hash('ab5'), pg_temp.t_x402_hash('f40'), 'pending',  repeat('5', 89),   'x402_payment_signature_format',    'a signature of 89 digits'),
      (pg_temp.t_x402_hash('ab5'), pg_temp.t_x402_hash('f40'), 'pending',  repeat('5', 87) || '0', 'x402_payment_signature_format', 'a signature with 0'),
      (pg_temp.t_x402_hash('ab5'), pg_temp.t_x402_hash('f40'), 'pending',  repeat('5', 87) || 'O', 'x402_payment_signature_format', 'a signature with O'),
      (pg_temp.t_x402_hash('ab5'), pg_temp.t_x402_hash('f40'), 'pending',  repeat('5', 87) || 'I', 'x402_payment_signature_format', 'a signature with I'),
      (pg_temp.t_x402_hash('ab5'), pg_temp.t_x402_hash('f40'), 'pending',  repeat('5', 87) || 'l', 'x402_payment_signature_format', 'a signature with l'),
      (pg_temp.t_x402_hash('ab5'), pg_temp.t_x402_hash('f40'), 'pending',  repeat('5', 87) || '+', 'x402_payment_signature_format', 'a signature with +'),
      (pg_temp.t_x402_hash('ab5'), pg_temp.t_x402_hash('f40'), 'pending',  '',                'x402_payment_signature_format',    'an empty signature')
    ) AS t (message_hash, source_hash, status, signature, constraint_name, what)
  LOOP
    BEGIN
      INSERT INTO x402_payment (message_hash, source_hash, status, signature) VALUES (bad.message_hash, bad.source_hash, bad.status, bad.signature);
      ASSERT false, bad.what || ' is refused';
    EXCEPTION WHEN check_violation THEN
      GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
      ASSERT refused_by = bad.constraint_name, bad.constraint_name || ' refuses ' || bad.what || ', not ' || refused_by;
    END;
  END LOOP;

  INSERT INTO x402_payment (message_hash, source_hash, status, signature) VALUES
    (pg_temp.t_x402_hash('ab6'), pg_temp.t_x402_hash('f41'), 'pending', repeat('1', 64)),
    (pg_temp.t_x402_hash('ab7'), pg_temp.t_x402_hash('f42'), 'pending', '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' || repeat('z', 30)),
    (pg_temp.t_x402_hash('ab8'), pg_temp.t_x402_hash('f43'), 'pending', NULL);
  ASSERT (SELECT array_agg(length(signature) ORDER BY message_hash) FROM x402_payment
           WHERE message_hash IN (pg_temp.t_x402_hash('ab6'), pg_temp.t_x402_hash('ab7'), pg_temp.t_x402_hash('ab8')))
         = ARRAY[64, 88, NULL],
         'a signature of 64 digits, one of 88 digits that holds every base58 digit, and a pending row with no signature are written';

  BEGIN
    PERFORM api.fn_x402_payment_reserve(repeat('A', 64), pg_temp.t_x402_hash('f44'));
    ASSERT false, 'a reserve of an upper case message hash is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'x402_payment_message_hash_format', 'x402_payment_message_hash_format refuses the reserve of an upper case message hash';
  END;
  BEGIN
    PERFORM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('ab9'), repeat('F', 64));
    ASSERT false, 'a reserve of an upper case source hash is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'x402_payment_source_hash_format', 'x402_payment_source_hash_format refuses the reserve of an upper case source hash';
  END;
  BEGIN
    PERFORM api.fn_x402_payment_reserve(NULL, pg_temp.t_x402_hash('f44'));
    ASSERT false, 'a reserve of a NULL message hash is refused';
  EXCEPTION WHEN not_null_violation THEN
    NULL;
  END;
  BEGIN
    PERFORM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('ab9'), NULL);
    ASSERT false, 'a reserve of a NULL source hash is refused';
  EXCEPTION WHEN not_null_violation THEN
    NULL;
  END;
  INSERT INTO x402_payment (message_hash, source_hash, status) VALUES (pg_temp.t_x402_hash('ab10'), pg_temp.t_x402_hash('f45'), 'reserved');
  BEGIN
    PERFORM api.fn_x402_payment_mark_pending(pg_temp.t_x402_hash('ab10'), 'not base58');
    ASSERT false, 'a mark_pending with a text that is not base58 is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'x402_payment_signature_format', 'x402_payment_signature_format refuses a mark_pending with a text that is not base58';
  END;
  ASSERT (SELECT row(status, signature)::text FROM x402_payment WHERE message_hash = pg_temp.t_x402_hash('ab10')) = row('reserved', NULL)::text,
         'the refused mark_pending leaves the row reserved';
  BEGIN
    INSERT INTO x402_payment (message_hash, source_hash, status) VALUES (pg_temp.t_x402_hash('ab10'), pg_temp.t_x402_hash('f45'), 'reserved');
    ASSERT false, 'a second row of one message is refused';
  EXCEPTION WHEN unique_violation THEN
    NULL;
  END;
END
$$;

INSERT INTO x402_payment (message_hash, source_hash, status, signature, reserved_at) VALUES
  (pg_temp.t_x402_hash('ad1'), pg_temp.t_x402_hash('f60'), 'pending',  NULL,            now() - interval '151 seconds'),
  (pg_temp.t_x402_hash('ad2'), pg_temp.t_x402_hash('f61'), 'pending',  repeat('5', 88), now() - interval '151 seconds'),
  (pg_temp.t_x402_hash('ad3'), pg_temp.t_x402_hash('f62'), 'reserved', NULL,            now() - interval '151 seconds');

DO $$
DECLARE
  old_level text := current_setting('client_min_messages');
BEGIN
  ASSERT (SELECT array_agg(r.reserve_answer || '/' || coalesce(length(r.signature)::text, '-') ORDER BY n)
            FROM (VALUES (1, 'ad1', 'f60'), (2, 'ad2', 'f61'), (3, 'ad3', 'f62')) AS v (n, m, s),
                 LATERAL api.fn_x402_payment_reserve(pg_temp.t_x402_hash(v.m), pg_temp.t_x402_hash(v.s)) AS r)
         = ARRAY['pending/-', 'pending/88', 'in_flight/-'],
         'a reserve of a pending or reserved row of a free source answers from the row';
  ASSERT (SELECT array_agg(row(right(message_hash, 3), status, length(signature), reserved_at = now() - interval '151 seconds')::text ORDER BY message_hash)
            FROM x402_payment WHERE source_hash IN (pg_temp.t_x402_hash('f60'), pg_temp.t_x402_hash('f61'), pg_temp.t_x402_hash('f62')))
         = ARRAY[row('ad1', 'pending', NULL::int, true)::text, row('ad2', 'pending', 88, true)::text, row('ad3', 'reserved', NULL::int, true)::text],
         'the reserve leaves the pending and the reserved row, and their reserved_at, as they were';

  PERFORM api.fn_x402_payment_reserve(pg_temp.t_x402_hash('ae1'), pg_temp.t_x402_hash('f63'));
  ASSERT EXISTS (SELECT FROM pg_locks AS l
                  WHERE l.locktype = 'advisory' AND l.pid = pg_backend_pid() AND l.granted AND l.objsubid = 2
                    AND l.classid = hashtext('x402_payment')::oid AND l.objid = hashtext(pg_temp.t_x402_hash('f63'))::oid),
         'the reserve holds the advisory lock of its source';
  PERFORM set_config('client_min_messages', 'error', true);
  ASSERT NOT pg_advisory_unlock(hashtext('x402_payment'), hashtext(pg_temp.t_x402_hash('f63'))),
         'the source lock is a transaction lock, so no session lock is left to release';
  PERFORM set_config('client_min_messages', old_level, true);
END
$$;

INSERT INTO x402_payment (message_hash, source_hash, status, signature, reserved_at) VALUES
  (pg_temp.t_x402_hash('ac1'), pg_temp.t_x402_hash('f50'), 'reserved', NULL,            now() - interval '1 hour 1 second'),
  (pg_temp.t_x402_hash('ac2'), pg_temp.t_x402_hash('f50'), 'pending',  repeat('5', 88), now() - interval '1 hour 1 second'),
  (pg_temp.t_x402_hash('ac3'), pg_temp.t_x402_hash('f50'), 'settled',  NULL,            now() - interval '1 hour 1 second'),
  (pg_temp.t_x402_hash('ac4'), pg_temp.t_x402_hash('f50'), 'released', NULL,            now() - interval '1 hour 1 second'),
  (pg_temp.t_x402_hash('ac5'), pg_temp.t_x402_hash('f51'), 'settled',  NULL,            now() - interval '1 hour'),
  (pg_temp.t_x402_hash('ac6'), pg_temp.t_x402_hash('f51'), 'reserved', NULL,            now() - interval '59 minutes 59 seconds'),
  (pg_temp.t_x402_hash('ac7'), pg_temp.t_x402_hash('f51'), 'pending',  repeat('5', 88), now() - interval '59 minutes 59 seconds'),
  (pg_temp.t_x402_hash('ac8'), pg_temp.t_x402_hash('f51'), 'settled',  NULL,            now() - interval '59 minutes 59 seconds'),
  (pg_temp.t_x402_hash('ac9'), pg_temp.t_x402_hash('f51'), 'released', NULL,            now() - interval '59 minutes 59 seconds');

DO $$
DECLARE
  young_row_count bigint := (SELECT count(*) FROM x402_payment WHERE reserved_at >= now() - interval '1 hour');
BEGIN
  ASSERT api.fn_x402_payment_purge(NULL) IS NULL, 'a NULL limit answers NULL';
  ASSERT (SELECT count(*) FROM x402_payment WHERE source_hash = pg_temp.t_x402_hash('f50')) = 4, 'a NULL limit deletes nothing';
  ASSERT api.fn_x402_payment_purge(0) = 0, 'a limit of 0 deletes nothing';
  ASSERT api.fn_x402_payment_purge(1) = 1, 'a limit of 1 deletes one of the four old rows';
  ASSERT (SELECT count(*) FROM x402_payment WHERE source_hash = pg_temp.t_x402_hash('f50')) = 3, 'the limit of 1 left three old rows';
  ASSERT api.fn_x402_payment_purge(2) = 2, 'a limit of 2 deletes two more';
  ASSERT api.fn_x402_payment_purge(10) = 1, 'the next call deletes the last old row and answers 1';
  ASSERT api.fn_x402_payment_purge(10) = 0, 'a call with no old row deletes none';
  ASSERT (SELECT count(*) FROM x402_payment WHERE source_hash = pg_temp.t_x402_hash('f50')) = 0,
         'the old row of each status is deleted';
  ASSERT (SELECT array_agg(right(message_hash, 3) ORDER BY message_hash) FROM x402_payment WHERE source_hash = pg_temp.t_x402_hash('f51'))
         = ARRAY['ac5', 'ac6', 'ac7', 'ac8', 'ac9'],
         'a row reserved exactly one hour ago and the row of each status reserved 59 minutes 59 seconds ago stay';
  ASSERT (SELECT count(*) FROM x402_payment) = young_row_count, 'the purge deleted no row reserved one hour ago or less';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(p.oid::regprocedure::text, p.prosecdef, p.proisstrict, p.provolatile, p.proconfig::text)::text ORDER BY p.oid::regprocedure::text)
            FROM pg_proc AS p WHERE p.pronamespace = 'api'::regnamespace AND p.proname LIKE 'fn\_x402\_%')
         = ARRAY[row('api.fn_x402_payment_mark_pending(text,text)', true, false, 'v', '{search_path=pg_catalog}')::text,
                 row('api.fn_x402_payment_mark_settled(text)',      true, false, 'v', '{search_path=pg_catalog}')::text,
                 row('api.fn_x402_payment_purge(integer)',          true, true,  'v', '{search_path=pg_catalog}')::text,
                 row('api.fn_x402_payment_release(text)',           true, false, 'v', '{search_path=pg_catalog}')::text,
                 row('api.fn_x402_payment_reserve(text,text)',      true, false, 'v', '{search_path=pg_catalog}')::text],
         'the five x402 functions are SECURITY DEFINER and VOLATILE, set search_path to pg_catalog, and only the purge is STRICT';
  ASSERT (SELECT array_agg(format_type(p.prorettype, NULL) ORDER BY p.proname) FROM pg_proc AS p
           WHERE p.pronamespace = 'api'::regnamespace AND p.proname LIKE 'fn\_x402\_%' AND p.proname <> 'fn_x402_payment_reserve')
         = ARRAY['boolean', 'boolean', 'integer', 'boolean'],
         'mark_pending, mark_settled and release answer boolean, and the purge answers integer';
  ASSERT (SELECT relpersistence FROM pg_class WHERE oid = 'x402_payment'::regclass) = 'p', 'x402_payment is a logged table';
  ASSERT (SELECT array_agg(indexdef ORDER BY indexname) FROM pg_indexes WHERE tablename = 'x402_payment')
         = ARRAY['CREATE INDEX idx_x402_payment_reserved_at ON public.x402_payment USING btree (reserved_at)',
                 'CREATE INDEX idx_x402_payment_source_hash_reserved_at ON public.x402_payment USING btree (source_hash, reserved_at)',
                 'CREATE UNIQUE INDEX x402_payment_pkey ON public.x402_payment USING btree (message_hash)'],
         'x402_payment has its primary key, an index of source_hash and reserved_at, and an index of reserved_at';
END
$$;
