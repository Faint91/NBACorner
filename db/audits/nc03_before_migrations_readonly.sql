-- NC-04 DESIGN ONLY: never executed against production in NC-03.
-- Secured-baseline-compatible counts; no identities, hashes or reset tokens returned.
-- Review schema fingerprint first; stop on missing/unexpected baseline objects.
BEGIN READ ONLY;
SET LOCAL statement_timeout='30s';
SELECT table_name,column_name,data_type,is_nullable FROM information_schema.columns
 WHERE table_schema='public' ORDER BY table_name,ordinal_position;
WITH names AS (SELECT lower(btrim(name,U&'\0009\000A\000B\000C\000D\001C\001D\001E\001F\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')) AS key FROM public.leagues)
SELECT '0008_normalized_league_collision_groups' AS check_name,count(*) AS finding_count
 FROM (SELECT key FROM names GROUP BY key HAVING count(*)>1) duplicates;
SELECT '0008_invalid_or_untrimmed_names' AS check_name,count(*) AS finding_count FROM public.leagues
 WHERE name IS NULL OR name IS DISTINCT FROM btrim(name,U&'\0009\000A\000B\000C\000D\001C\001D\001E\001F\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000') OR char_length(name) NOT BETWEEN 1 AND 80;
SELECT '0008_owner_not_member' AS check_name,count(*) AS finding_count FROM public.leagues l
 WHERE NOT EXISTS(SELECT 1 FROM public.league_members m WHERE m.league_id=l.id AND m.user_id=l.owner_user_id);
SELECT '0008_duplicate_membership_groups' AS check_name,count(*) AS finding_count
 FROM (SELECT league_id,user_id FROM public.league_members GROUP BY league_id,user_id HAVING count(*)>1) duplicates;
WITH identities AS (SELECT lower(btrim(username,U&'\0009\000A\000B\000C\000D\001C\001D\001E\001F\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')) AS name_key,lower(btrim(email,U&'\0009\000A\000B\000C\000D\001C\001D\001E\001F\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')) AS email_key FROM public.users)
SELECT '0010_invalid_identities' AS check_name,count(*) AS finding_count FROM identities
 WHERE name_key IS NULL OR email_key IS NULL OR name_key='' OR email_key='';
WITH identities AS (SELECT lower(btrim(username,U&'\0009\000A\000B\000C\000D\001C\001D\001E\001F\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')) AS key FROM public.users)
SELECT '0010_username_collision_groups' AS check_name,count(*) AS finding_count FROM (SELECT key FROM identities GROUP BY key HAVING count(*)>1) duplicates;
WITH identities AS (SELECT lower(btrim(email,U&'\0009\000A\000B\000C\000D\001C\001D\001E\001F\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')) AS key FROM public.users)
SELECT '0010_email_collision_groups' AS check_name,count(*) AS finding_count FROM (SELECT key FROM identities GROUP BY key HAVING count(*)>1) duplicates;
SELECT '0011_outstanding_legacy_reset_rows_to_invalidate' AS check_name,count(*) AS finding_count FROM public.password_resets;
SELECT '0011_legacy_user_reset_fields_to_clear' AS check_name,count(*) AS finding_count FROM public.users WHERE reset_token IS NOT NULL OR reset_token_expires IS NOT NULL;
SELECT '0001_active_user_season_duplicates' AS check_name,count(*) AS finding_count FROM (SELECT user_id,season_id FROM public.brackets WHERE deleted_at IS NULL GROUP BY user_id,season_id HAVING count(*)>1) duplicates;
SELECT '0001_active_master_duplicates' AS check_name,count(*) AS finding_count FROM (SELECT season_id FROM public.brackets WHERE deleted_at IS NULL AND is_master IS TRUE GROUP BY season_id HAVING count(*)>1) duplicates;
SELECT 'orphan_bracket_users' AS check_name,count(*) AS finding_count FROM public.brackets b WHERE b.user_id IS NULL OR NOT EXISTS(SELECT 1 FROM public.users u WHERE u.id=b.user_id);
SELECT 'invalid_season_timing' AS check_name,count(*) AS finding_count FROM public.seasons WHERE regular_season_end_utc IS NULL OR playoffs_start_utc IS NULL OR regular_season_end_utc>=playoffs_start_utc;
SELECT 'inconsistent_master_pointers' AS check_name,count(*) AS finding_count FROM public.seasons s WHERE s.master_bracket_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.brackets b WHERE b.id=s.master_bracket_id AND b.season_id=s.id AND b.is_master IS TRUE AND b.deleted_at IS NULL);
SELECT 'legacy_history_headers' AS check_name,count(*) AS finding_count FROM public.leaderboard_history_snapshots;
SELECT 'orphan_history_rows' AS check_name,count(*) AS finding_count FROM public.leaderboard_history_rows r WHERE NOT EXISTS(SELECT 1 FROM public.leaderboard_history_snapshots h WHERE h.id=r.snapshot_id);
SELECT 'standings_rows_not_a_uniqueness_claim' AS check_name,count(*) AS finding_count FROM public.standings;
COMMIT;
