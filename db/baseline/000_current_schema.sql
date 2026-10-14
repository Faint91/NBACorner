-- Consolidated current-state secured bootstrap; NOT historical migration history.
-- Only for positively verified EMPTY NON-PRODUCTION targets in a later phase.
-- Catalog guards do not establish environment identity. No rows or seeds copied.
BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL statement_timeout = '60s';
SET LOCAL lock_timeout = '5s';
SET LOCAL standard_conforming_strings = on;
SET LOCAL search_path = public, pg_catalog;
SET LOCAL check_function_bodies = false;
DO $baseline_preflight$
BEGIN
  IF (SELECT current_user) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: execution role';
  END IF;
  IF (SELECT current_setting('server_version_num')::integer >= 170000) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: PostgreSQL >=17; newer major needs review';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='postgres')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: role postgres';
  END IF;
  IF (SELECT has_schema_privilege('postgres','public','USAGE')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: public USAGE postgres';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: role anon';
  END IF;
  IF (SELECT has_schema_privilege('anon','public','USAGE')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: public USAGE anon';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: role authenticated';
  END IF;
  IF (SELECT has_schema_privilege('authenticated','public','USAGE')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: public USAGE authenticated';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: role service_role';
  END IF;
  IF (SELECT has_schema_privilege('service_role','public','USAGE')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: public USAGE service_role';
  END IF;
  IF (SELECT to_regnamespace('public') IS NOT NULL) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: schema public';
  END IF;
  IF (SELECT to_regnamespace('auth') IS NOT NULL) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: schema auth';
  END IF;
  IF (SELECT to_regnamespace('extensions') IS NOT NULL) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: schema extensions';
  END IF;
  IF (SELECT prorettype='uuid'::regtype FROM pg_proc WHERE oid=to_regprocedure('auth.uid()')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: platform function auth.uid()';
  END IF;
  IF (SELECT prorettype='uuid'::regtype FROM pg_proc WHERE oid=to_regprocedure('extensions.uuid_generate_v4()')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: platform function extensions.uuid_generate_v4()';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='plpgsql')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: extension plpgsql';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='uuid-ossp')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: extension uuid-ossp';
  END IF;
  IF (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE((SELECT defaclacl FROM pg_default_acl WHERE defaclrole='postgres'::regrole AND defaclnamespace=0 AND defaclobjtype='f'),acldefault('f','postgres'::regrole))) x) IS DISTINCT FROM 'PUBLIC:EXECUTE:false:postgres,postgres:EXECUTE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: unchanged supplied function defaults 0';
  END IF;
  IF (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE((SELECT defaclacl FROM pg_default_acl WHERE defaclrole='postgres'::regrole AND defaclnamespace='public'::regnamespace AND defaclobjtype='f'),ARRAY[]::aclitem[])) x) IS DISTINCT FROM 'anon:EXECUTE:false:postgres,authenticated:EXECUTE:false:postgres,postgres:EXECUTE:false:postgres,service_role:EXECUTE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: unchanged supplied function defaults ''public''::regnamespace';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class c WHERE c.relnamespace='public'::regnamespace
    AND c.relkind IN ('r','p','v','m','S','f') AND NOT EXISTS (SELECT 1 FROM pg_depend d
      WHERE d.classid='pg_class'::regclass AND d.objid=c.oid AND d.deptype='e'))
    OR EXISTS (SELECT 1 FROM pg_proc p WHERE p.pronamespace='public'::regnamespace
      AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')) THEN
    RAISE EXCEPTION 'Requires empty application namespace; no replacement/reset permitted';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_default_acl a, LATERAL aclexplode(a.defaclacl) x
    WHERE a.defaclrole='postgres'::regrole AND a.defaclnamespace=0 AND a.defaclobjtype IN ('r','S')
      AND (x.grantee<>'postgres'::regrole OR x.is_grantable)) THEN
    RAISE EXCEPTION 'Unexpected global relation defaults; scoped revoke cannot cancel global grants';
  END IF;
END
$baseline_preflight$;
SELECT set_config('nbacorner_baseline.platform_before', (SELECT md5(jsonb_build_object(
  'schemas',(SELECT jsonb_agg(jsonb_build_array(nspname,nspowner,nspacl) ORDER BY nspname) FROM pg_namespace),
  'roles',(SELECT jsonb_agg(jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls) ORDER BY rolname) FROM pg_roles),
  'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY roleid,member,grantor) FROM pg_auth_members m),
  'extensions',(SELECT jsonb_agg(jsonb_build_array(extname,extowner,extnamespace,extversion) ORDER BY extname) FROM pg_extension),
  'other_defaults',(SELECT jsonb_agg(to_jsonb(a) ORDER BY defaclrole,defaclnamespace,defaclobjtype) FROM pg_default_acl a
    WHERE NOT (defaclrole='postgres'::regrole AND defaclnamespace='public'::regnamespace AND defaclobjtype IN ('r','S')))
)::text)), true);

-- Application DDL preserved from NC-00 audit.
CREATE FUNCTION "public"."_set_bracket_scores_season_id"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  SELECT season_id INTO NEW.season_id FROM public.brackets WHERE id = NEW.bracket_id;
  RETURN NEW;
END $$;

ALTER FUNCTION "public"."_set_bracket_scores_season_id"() OWNER TO "postgres";

CREATE FUNCTION "public"."_set_matches_season_id"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  SELECT season_id INTO NEW.season_id FROM public.brackets WHERE id = NEW.bracket_id;
  RETURN NEW;
END $$;

ALTER FUNCTION "public"."_set_matches_season_id"() OWNER TO "postgres";

CREATE FUNCTION "public"."atomic_update_match"("p_match_id" "uuid", "p_action" "text", "p_new_team" "text" DEFAULT NULL::"text", "p_games" integer DEFAULT NULL::integer) RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
declare
  cur_match record;
  old_winner text;
  next_id uuid;
  nm record;
begin
  perform 1;
  -- load match
  select * into cur_match from matches where id = p_match_id;
  if cur_match is null then
    return json_build_object('ok', false, 'message', 'match not found');
  end if;

  if p_action = 'set_games' then
    update matches set predicted_winner_games = p_games, updated_at = now() where id = p_match_id;
    return json_build_object('ok', true, 'message', 'games updated');
  elsif p_action = 'set_winner' then
    if p_new_team is null then
      return json_build_object('ok', false, 'message', 'missing p_new_team');
    end if;

    old_winner := cur_match.predicted_winner;

    -- set this match's winner & games
    update matches set predicted_winner = p_new_team,
                       predicted_winner_games = p_games,
                       updated_at = now()
    where id = p_match_id;

    -- clear descendants that involve old_winner (only if old_winner not null)
    if old_winner is not null and old_winner <> p_new_team then
      next_id := cur_match.next_match_id;
      while next_id is not null loop
        select * into nm from matches where id = next_id;
        exit when nm is null;

        -- if nm.predicted_winner == old_winner -> clear it
        if nm.predicted_winner = old_winner then
          update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now()
          where id = nm.id;
        end if;

        -- if team_a == old_winner and team_a not locked -> remove it
        if nm.team_a = old_winner and (nm.team_a_locked is distinct from true) then
          update matches set team_a = null, updated_at = now() where id = nm.id;
        end if;

        -- same for team_b
        if nm.team_b = old_winner and (nm.team_b_locked is distinct from true) then
          update matches set team_b = null, updated_at = now() where id = nm.id;
        end if;

        next_id := nm.next_match_id;
      end loop;
    end if;

    -- place new_team into immediate next_match slot (but do NOT set predicted_winner there)
    if cur_match.next_match_id is not null then
      select * into nm from matches where id = cur_match.next_match_id;
      if nm is not null then
        if cur_match.next_slot = 'a' then
          if nm.team_a_locked is distinct from true then
            update matches set team_a = p_new_team, predicted_winner = null, predicted_winner_games = null, updated_at = now()
            where id = nm.id;
          end if;
        else
          if nm.team_b_locked is distinct from true then
            update matches set team_b = p_new_team, predicted_winner = null, predicted_winner_games = null, updated_at = now()
            where id = nm.id;
          end if;
        end if;
      end if;
    end if;

    return json_build_object('ok', true, 'message', 'winner set');
  elsif p_action = 'undo' then
    old_winner := cur_match.predicted_winner;
    if old_winner is null then
      return json_build_object('ok', true, 'message', 'nothing to undo');
    end if;

    -- clear this match
    update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = p_match_id;

    -- clear propagated descendants and remove from slots (if not locked)
    next_id := cur_match.next_match_id;
    while next_id is not null loop
      select * into nm from matches where id = next_id;
      exit when nm is null;

      if nm.team_a = old_winner and (nm.team_a_locked is distinct from true) then
        update matches set team_a = null, updated_at = now() where id = nm.id;
      end if;
      if nm.team_b = old_winner and (nm.team_b_locked is distinct from true) then
        update matches set team_b = null, updated_at = now() where id = nm.id;
      end if;
      if nm.predicted_winner = old_winner then
        update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = nm.id;
      end if;

      next_id := nm.next_match_id;
    end loop;

    return json_build_object('ok', true, 'message', 'undo complete');
  else
    return json_build_object('ok', false, 'message', 'invalid action');
  end if;

end;
$$;

ALTER FUNCTION "public"."atomic_update_match"("p_match_id" "uuid", "p_action" "text", "p_new_team" "text", "p_games" integer) OWNER TO "postgres";

CREATE FUNCTION "public"."fix_season_master_on_bracket_soft_delete"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  -- Act only on transition to soft-deleted
  IF TG_OP = 'UPDATE'
     AND NEW.deleted_at IS NOT NULL
     AND (OLD.deleted_at IS NULL OR OLD.deleted_at <> NEW.deleted_at) THEN

    -- Demote master flag on the row being updated (avoid recursive UPDATE by assigning NEW)
    IF NEW.is_master IS TRUE THEN
      NEW.is_master := FALSE;
    END IF;

    -- If the season points to this bracket, null it out
    UPDATE public.seasons
       SET master_bracket_id = NULL
     WHERE id = NEW.season_id
       AND master_bracket_id = NEW.id;
  END IF;

  RETURN NEW;
END
$$;

ALTER FUNCTION "public"."fix_season_master_on_bracket_soft_delete"() OWNER TO "postgres";

CREATE FUNCTION "public"."set_master_bracket"("season_id" "uuid", "bracket_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  prev_master uuid;
BEGIN
  -- Safety: make sure the bracket belongs to that season
  IF NOT EXISTS (
    SELECT 1 FROM public.brackets b
    WHERE b.id = bracket_id AND b.season_id = season_id
  ) THEN
    RAISE EXCEPTION 'Bracket % does not belong to season %', bracket_id, season_id;
  END IF;

  -- Lock the season row to avoid races
  SELECT master_bracket_id
    INTO prev_master
  FROM public.seasons
  WHERE id = season_id
  FOR UPDATE;

  -- Demote prior master (if any)
  IF prev_master IS NOT NULL AND prev_master <> bracket_id THEN
    UPDATE public.brackets
    SET is_master = FALSE
    WHERE id = prev_master;
  END IF;

  -- Promote the new master
  UPDATE public.brackets
  SET is_master = TRUE
  WHERE id = bracket_id;

  -- Point season to the new master
  UPDATE public.seasons
  SET master_bracket_id = bracket_id
  WHERE id = season_id;
END;
$$;

ALTER FUNCTION "public"."set_master_bracket"("season_id" "uuid", "bracket_id" "uuid") OWNER TO "postgres";

CREATE FUNCTION "public"."set_winner_atomic"("in_match" "uuid", "in_new_team" "text", "in_games" integer) RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
declare
  start_row record;
  old_winner text;
  next_id uuid;
  nm record;
  cur_id uuid;
  affected_count integer := 0;
begin
  -- lock the starting match row
  select * into start_row from matches where id = in_match for update;
  if start_row is null then
    return jsonb_build_object('ok', false, 'error', 'match_not_found');
  end if;

  old_winner := start_row.predicted_winner;

  -- update this match with the new prediction
  update matches set predicted_winner = in_new_team,
                     predicted_winner_games = in_games,
                     updated_at = now()
    where id = in_match;

  affected_count := affected_count + 1;

  -- If there was an old winner, walk forward and clear it wherever it appears due to predictions
  cur_id := in_match;
  while true loop
    select next_match_id into next_id from matches where id = cur_id;
    if next_id is null then
      exit;
    end if;

    -- lock the child row
    select * into nm from matches where id = next_id for update;
    if nm is null then
      exit;
    end if;

    -- If nm.predicted_winner was the old_winner, clear it
    if old_winner is not null then
      if nm.predicted_winner = old_winner then
        update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = nm.id;
        affected_count := affected_count + 1;
      end if;

      -- If old_winner was placed into team_a or team_b (because it was advanced previously), clear that slot.
      if nm.team_a = old_winner then
        update matches set team_a = null, updated_at = now() where id = nm.id;
        affected_count := affected_count + 1;
      end if;
      if nm.team_b = old_winner then
        update matches set team_b = null, updated_at = now() where id = nm.id;
        affected_count := affected_count + 1;
      end if;
    end if;

    -- continue down the chain
    cur_id := nm.id;
  end loop;

  -- Place the new winner in the immediate next match slot (if exists), but keep predicted_winner null for that next match
  select next_match_id into next_id from matches where id = in_match;
  if next_id is not null then
    select * into nm from matches where id = next_id for update;
    if nm is not null then
      if (select next_slot from matches where id = in_match) = 'a' then
        update matches set team_a = in_new_team, predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = nm.id;
      else
        update matches set team_b = in_new_team, predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = nm.id;
      end if;
      affected_count := affected_count + 1;
    end if;
  end if;

  return jsonb_build_object('ok', true, 'affected', affected_count);
end;
$$;

ALTER FUNCTION "public"."set_winner_atomic"("in_match" "uuid", "in_new_team" "text", "in_games" integer) OWNER TO "postgres";

CREATE FUNCTION "public"."undo_prediction_atomic"("in_match" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql"
    AS $$
declare
  start_row record;
  old_winner text;
  next_id uuid;
  nm record;
  cur_id uuid;
  affected_count integer := 0;
begin
  select * into start_row from matches where id = in_match for update;
  if start_row is null then
    return jsonb_build_object('ok', false, 'error', 'match_not_found');
  end if;

  old_winner := start_row.predicted_winner;

  -- clear this match
  update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = in_match;
  affected_count := affected_count + 1;

  -- walk forward and remove old_winner from slots and clear downstream predictions
  cur_id := in_match;
  while true loop
    select next_match_id into next_id from matches where id = cur_id;
    if next_id is null then
      exit;
    end if;

    select * into nm from matches where id = next_id for update;
    if nm is null then
      exit;
    end if;

    if nm.team_a = old_winner then
      update matches set team_a = null, updated_at = now() where id = nm.id;
      affected_count := affected_count + 1;
    end if;
    if nm.team_b = old_winner then
      update matches set team_b = null, updated_at = now() where id = nm.id;
      affected_count := affected_count + 1;
    end if;
    if nm.predicted_winner = old_winner then
      update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = nm.id;
      affected_count := affected_count + 1;
    end if;

    cur_id := nm.id;
  end loop;

  return jsonb_build_object('ok', true, 'affected', affected_count);
end;
$$;

ALTER FUNCTION "public"."undo_prediction_atomic"("in_match" "uuid") OWNER TO "postgres";

CREATE TABLE "public"."bracket_scores" (
    "bracket_id" "uuid" NOT NULL,
    "master_bracket_id" "uuid" NOT NULL,
    "total_points" integer DEFAULT 0 NOT NULL,
    "full_hits" integer DEFAULT 0 NOT NULL,
    "partial_hits" integer DEFAULT 0 NOT NULL,
    "misses" integer DEFAULT 0 NOT NULL,
    "bonus_finalists" integer DEFAULT 0 NOT NULL,
    "bonus_champion" integer DEFAULT 0 NOT NULL,
    "points_by_round" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "points_by_match" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "season_id" "uuid" NOT NULL,
    CONSTRAINT "bracket_scores_bonus_champion_check" CHECK (("bonus_champion" >= 0)),
    CONSTRAINT "bracket_scores_bonus_finalists_check" CHECK (("bonus_finalists" >= 0)),
    CONSTRAINT "bracket_scores_full_hits_check" CHECK (("full_hits" >= 0)),
    CONSTRAINT "bracket_scores_misses_check" CHECK (("misses" >= 0)),
    CONSTRAINT "bracket_scores_partial_hits_check" CHECK (("partial_hits" >= 0)),
    CONSTRAINT "bracket_scores_total_points_check" CHECK (("total_points" >= 0))
);

ALTER TABLE "public"."bracket_scores" OWNER TO "postgres";

CREATE TABLE "public"."brackets" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "is_done" boolean DEFAULT false,
    "saved_at" timestamp with time zone,
    "deleted_at" timestamp with time zone,
    "deleted_by_user_id" "uuid",
    "name" "text",
    "is_master" boolean DEFAULT false NOT NULL,
    "season_id" "uuid" NOT NULL
);

ALTER TABLE "public"."brackets" OWNER TO "postgres";

CREATE TABLE "public"."matches" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "bracket_id" "uuid" NOT NULL,
    "round" integer NOT NULL,
    "slot" integer NOT NULL,
    "team_a" "text",
    "team_b" "text",
    "team_a_locked" boolean DEFAULT false,
    "team_b_locked" boolean DEFAULT false,
    "predicted_winner" "text",
    "predicted_winner_games" integer,
    "next_match_id" "uuid",
    "next_slot" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "conference" "text" DEFAULT 'East'::"text",
    "season_id" "uuid" NOT NULL,
    CONSTRAINT "matches_next_slot_check" CHECK (("next_slot" = ANY (ARRAY['a'::"text", 'b'::"text"])))
);

ALTER TABLE "public"."matches" OWNER TO "postgres";

CREATE VIEW "public"."bracket_view" AS
 SELECT "m"."id",
    "m"."bracket_id",
    "m"."round",
    "m"."slot",
    "m"."team_a",
    "m"."team_b",
    "m"."team_a_locked",
    "m"."team_b_locked",
    "m"."predicted_winner",
    "m"."predicted_winner_games",
    "m"."next_match_id",
    "m"."next_slot",
    "m"."created_at",
    "m"."updated_at",
    "b"."user_id"
   FROM ("public"."matches" "m"
     JOIN "public"."brackets" "b" ON (("b"."id" = "m"."bracket_id")));

CREATE TABLE "public"."leaderboard_history" (
    "id" bigint NOT NULL,
    "season_id" "uuid" NOT NULL,
    "season_code" "text" NOT NULL,
    "snapshot_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "rank" integer NOT NULL,
    "bracket_name" "text" NOT NULL,
    "username" "text" NOT NULL,
    "total_points" integer NOT NULL,
    "full_hits" integer NOT NULL,
    "partial_hits" integer NOT NULL,
    "misses" integer NOT NULL,
    "bonus_finalists" integer NOT NULL,
    "bonus_champion" integer NOT NULL,
    "points_by_match" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "bracket_id" "uuid",
    "user_id" "uuid",
    CONSTRAINT "leaderboard_history_bonus_champion_check" CHECK (("bonus_champion" >= 0)),
    CONSTRAINT "leaderboard_history_bonus_finalists_check" CHECK (("bonus_finalists" >= 0)),
    CONSTRAINT "leaderboard_history_full_hits_check" CHECK (("full_hits" >= 0)),
    CONSTRAINT "leaderboard_history_misses_check" CHECK (("misses" >= 0)),
    CONSTRAINT "leaderboard_history_partial_hits_check" CHECK (("partial_hits" >= 0)),
    CONSTRAINT "leaderboard_history_rank_check" CHECK (("rank" > 0)),
    CONSTRAINT "leaderboard_history_total_points_check" CHECK (("total_points" >= 0))
);

ALTER TABLE "public"."leaderboard_history" OWNER TO "postgres";

CREATE SEQUENCE "public"."leaderboard_history_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE "public"."leaderboard_history_id_seq" OWNER TO "postgres";

ALTER SEQUENCE "public"."leaderboard_history_id_seq" OWNED BY "public"."leaderboard_history"."id";

CREATE TABLE "public"."leaderboard_history_rows" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "snapshot_id" "uuid" NOT NULL,
    "rank" integer,
    "display_name" "text" NOT NULL,
    "total_points" integer DEFAULT 0 NOT NULL,
    "bonus_finalists" integer DEFAULT 0 NOT NULL,
    "bonus_champion" integer DEFAULT 0 NOT NULL,
    "full_hits" integer DEFAULT 0 NOT NULL,
    "partial_hits" integer DEFAULT 0 NOT NULL,
    "misses" integer DEFAULT 0 NOT NULL,
    "per_match_points" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);

ALTER TABLE "public"."leaderboard_history_rows" OWNER TO "postgres";

CREATE TABLE "public"."leaderboard_history_snapshots" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "season_id" "uuid" NOT NULL,
    "season_code" "text" NOT NULL,
    "snapshot_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "columns" "jsonb" DEFAULT '[]'::"jsonb" NOT NULL,
    "note" "text",
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);

ALTER TABLE "public"."leaderboard_history_snapshots" OWNER TO "postgres";

CREATE TABLE "public"."league_members" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "league_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "joined_at" timestamp with time zone DEFAULT "now"() NOT NULL
);

ALTER TABLE "public"."league_members" OWNER TO "postgres";

CREATE TABLE "public"."leagues" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "name" "text" NOT NULL,
    "password_hash" "text",
    "owner_user_id" "uuid" NOT NULL,
    "is_global" boolean DEFAULT false NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);

ALTER TABLE "public"."leagues" OWNER TO "postgres";

CREATE TABLE "public"."password_resets" (
    "id" integer NOT NULL,
    "token" "text" NOT NULL,
    "expires_at" timestamp without time zone NOT NULL,
    "used" boolean DEFAULT false,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "user_id" "uuid"
);

ALTER TABLE "public"."password_resets" OWNER TO "postgres";

CREATE SEQUENCE "public"."password_resets_id_seq"
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE "public"."password_resets_id_seq" OWNER TO "postgres";

ALTER SEQUENCE "public"."password_resets_id_seq" OWNED BY "public"."password_resets"."id";

CREATE TABLE "public"."seasons" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "code" "text" NOT NULL,
    "regular_season_end_utc" timestamp with time zone,
    "playoffs_start_utc" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "master_bracket_id" "uuid"
);

ALTER TABLE "public"."seasons" OWNER TO "postgres";

CREATE TABLE "public"."standings" (
    "id" integer NOT NULL,
    "name" "text" NOT NULL,
    "code" "text" NOT NULL,
    "wins" integer DEFAULT 0 NOT NULL,
    "losses" integer DEFAULT 0 NOT NULL,
    "conference" "text" NOT NULL,
    "seed" integer,
    "updated_at" timestamp without time zone DEFAULT "now"(),
    "win_pct" double precision
);

ALTER TABLE "public"."standings" OWNER TO "postgres";

CREATE SEQUENCE "public"."standings_id_seq"
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE "public"."standings_id_seq" OWNER TO "postgres";

ALTER SEQUENCE "public"."standings_id_seq" OWNED BY "public"."standings"."id";

CREATE TABLE "public"."teams" (
    "id" "text" NOT NULL,
    "name" "text" NOT NULL,
    "conference" "text" NOT NULL,
    "code" "text" NOT NULL,
    "logo_url" "text",
    "primary_color" "text",
    "secondary_color" "text"
);

ALTER TABLE "public"."teams" OWNER TO "postgres";

CREATE TABLE "public"."users" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "username" "text" NOT NULL,
    "email" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "password" "text",
    "is_admin" boolean DEFAULT false,
    "reset_token" "text",
    "reset_token_expires" timestamp without time zone
);

ALTER TABLE "public"."users" OWNER TO "postgres";

ALTER TABLE ONLY "public"."leaderboard_history" ALTER COLUMN "id" SET DEFAULT "nextval"('"public"."leaderboard_history_id_seq"'::"regclass");

ALTER TABLE ONLY "public"."password_resets" ALTER COLUMN "id" SET DEFAULT "nextval"('"public"."password_resets_id_seq"'::"regclass");

ALTER TABLE ONLY "public"."standings" ALTER COLUMN "id" SET DEFAULT "nextval"('"public"."standings_id_seq"'::"regclass");

ALTER TABLE ONLY "public"."bracket_scores"
    ADD CONSTRAINT "bracket_scores_pkey" PRIMARY KEY ("bracket_id");

ALTER TABLE ONLY "public"."brackets"
    ADD CONSTRAINT "brackets_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."leaderboard_history"
    ADD CONSTRAINT "leaderboard_history_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."leaderboard_history_rows"
    ADD CONSTRAINT "leaderboard_history_rows_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."leaderboard_history_snapshots"
    ADD CONSTRAINT "leaderboard_history_snapshots_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."league_members"
    ADD CONSTRAINT "league_members_league_user_unique" UNIQUE ("league_id", "user_id");

ALTER TABLE ONLY "public"."league_members"
    ADD CONSTRAINT "league_members_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."leagues"
    ADD CONSTRAINT "leagues_name_unique" UNIQUE ("name");

ALTER TABLE ONLY "public"."leagues"
    ADD CONSTRAINT "leagues_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."matches"
    ADD CONSTRAINT "matches_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."password_resets"
    ADD CONSTRAINT "password_resets_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."password_resets"
    ADD CONSTRAINT "password_resets_token_key" UNIQUE ("token");

ALTER TABLE ONLY "public"."seasons"
    ADD CONSTRAINT "seasons_code_key" UNIQUE ("code");

ALTER TABLE ONLY "public"."seasons"
    ADD CONSTRAINT "seasons_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."standings"
    ADD CONSTRAINT "standings_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."teams"
    ADD CONSTRAINT "teams_code_key" UNIQUE ("code");

ALTER TABLE ONLY "public"."teams"
    ADD CONSTRAINT "teams_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."users"
    ADD CONSTRAINT "users_email_key" UNIQUE ("email");

ALTER TABLE ONLY "public"."users"
    ADD CONSTRAINT "users_email_unique" UNIQUE ("email");

ALTER TABLE ONLY "public"."users"
    ADD CONSTRAINT "users_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."users"
    ADD CONSTRAINT "users_username_unique" UNIQUE ("username");

CREATE INDEX "bracket_scores_master_idx" ON "public"."bracket_scores" USING "btree" ("master_bracket_id");

CREATE INDEX "bracket_scores_total_points_idx" ON "public"."bracket_scores" USING "btree" ("total_points");

CREATE INDEX "idx_bracket_scores_season_points" ON "public"."bracket_scores" USING "btree" ("season_id", "total_points" DESC);

CREATE INDEX "idx_brackets_season_created" ON "public"."brackets" USING "btree" ("season_id", "created_at" DESC);

CREATE INDEX "idx_brackets_user_id" ON "public"."brackets" USING "btree" ("user_id");

CREATE INDEX "idx_leaderboard_history_rows_snapshot" ON "public"."leaderboard_history_rows" USING "btree" ("snapshot_id");

CREATE INDEX "idx_leaderboard_history_season_rank" ON "public"."leaderboard_history" USING "btree" ("season_id", "rank");

CREATE INDEX "idx_leaderboard_history_snapshots_code" ON "public"."leaderboard_history_snapshots" USING "btree" ("season_code");

CREATE INDEX "idx_leaderboard_history_snapshots_season" ON "public"."leaderboard_history_snapshots" USING "btree" ("season_id");

CREATE INDEX "idx_matches_bracket" ON "public"."matches" USING "btree" ("bracket_id", "round");

CREATE INDEX "idx_matches_season_bracket" ON "public"."matches" USING "btree" ("season_id", "bracket_id");

CREATE INDEX "league_members_league_id_idx" ON "public"."league_members" USING "btree" ("league_id");

CREATE INDEX "league_members_user_id_idx" ON "public"."league_members" USING "btree" ("user_id");

CREATE UNIQUE INDEX "uniq_active_bracket_per_user_per_season" ON "public"."brackets" USING "btree" ("user_id", "season_id") WHERE ("deleted_at" IS NULL);

CREATE UNIQUE INDEX "unique_active_bracket_per_user" ON "public"."brackets" USING "btree" ("user_id") WHERE ("deleted_at" IS NULL);

CREATE UNIQUE INDEX "uq_master_per_season" ON "public"."brackets" USING "btree" ("season_id") WHERE (("is_master" IS TRUE) AND ("deleted_at" IS NULL));

CREATE UNIQUE INDEX "ux_brackets_one_master_per_season" ON "public"."brackets" USING "btree" ("season_id") WHERE ("is_master" = true);

CREATE TRIGGER "trg_bracket_scores_set_season" BEFORE INSERT OR UPDATE OF "bracket_id" ON "public"."bracket_scores" FOR EACH ROW EXECUTE FUNCTION "public"."_set_bracket_scores_season_id"();

CREATE TRIGGER "trg_fix_season_master_on_bracket_soft_delete" BEFORE UPDATE ON "public"."brackets" FOR EACH ROW EXECUTE FUNCTION "public"."fix_season_master_on_bracket_soft_delete"();

CREATE TRIGGER "trg_matches_set_season" BEFORE INSERT OR UPDATE OF "bracket_id" ON "public"."matches" FOR EACH ROW EXECUTE FUNCTION "public"."_set_matches_season_id"();

ALTER TABLE ONLY "public"."bracket_scores"
    ADD CONSTRAINT "bracket_scores_bracket_id_fkey" FOREIGN KEY ("bracket_id") REFERENCES "public"."brackets"("id") ON DELETE CASCADE;

ALTER TABLE ONLY "public"."bracket_scores"
    ADD CONSTRAINT "bracket_scores_master_bracket_id_fkey" FOREIGN KEY ("master_bracket_id") REFERENCES "public"."brackets"("id") ON DELETE CASCADE;

ALTER TABLE ONLY "public"."bracket_scores"
    ADD CONSTRAINT "bracket_scores_season_id_fkey" FOREIGN KEY ("season_id") REFERENCES "public"."seasons"("id");

ALTER TABLE ONLY "public"."brackets"
    ADD CONSTRAINT "brackets_season_id_fkey" FOREIGN KEY ("season_id") REFERENCES "public"."seasons"("id");

ALTER TABLE ONLY "public"."leaderboard_history_rows"
    ADD CONSTRAINT "leaderboard_history_rows_snapshot_id_fkey" FOREIGN KEY ("snapshot_id") REFERENCES "public"."leaderboard_history_snapshots"("id") ON DELETE CASCADE;

ALTER TABLE ONLY "public"."leaderboard_history"
    ADD CONSTRAINT "leaderboard_history_season_id_fkey" FOREIGN KEY ("season_id") REFERENCES "public"."seasons"("id");

ALTER TABLE ONLY "public"."leaderboard_history_snapshots"
    ADD CONSTRAINT "leaderboard_history_snapshots_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id");

ALTER TABLE ONLY "public"."leaderboard_history_snapshots"
    ADD CONSTRAINT "leaderboard_history_snapshots_season_id_fkey" FOREIGN KEY ("season_id") REFERENCES "public"."seasons"("id") ON DELETE CASCADE;

ALTER TABLE ONLY "public"."league_members"
    ADD CONSTRAINT "league_members_league_id_fkey" FOREIGN KEY ("league_id") REFERENCES "public"."leagues"("id") ON DELETE CASCADE;

ALTER TABLE ONLY "public"."league_members"
    ADD CONSTRAINT "league_members_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE CASCADE;

ALTER TABLE ONLY "public"."leagues"
    ADD CONSTRAINT "leagues_owner_user_id_fkey" FOREIGN KEY ("owner_user_id") REFERENCES "public"."users"("id");

ALTER TABLE ONLY "public"."matches"
    ADD CONSTRAINT "matches_bracket_id_fkey" FOREIGN KEY ("bracket_id") REFERENCES "public"."brackets"("id") ON DELETE CASCADE;

ALTER TABLE ONLY "public"."matches"
    ADD CONSTRAINT "matches_next_match_id_fkey" FOREIGN KEY ("next_match_id") REFERENCES "public"."matches"("id") ON DELETE SET NULL;

ALTER TABLE ONLY "public"."matches"
    ADD CONSTRAINT "matches_predicted_winner_fkey" FOREIGN KEY ("predicted_winner") REFERENCES "public"."teams"("id");

ALTER TABLE ONLY "public"."matches"
    ADD CONSTRAINT "matches_season_id_fkey" FOREIGN KEY ("season_id") REFERENCES "public"."seasons"("id");

ALTER TABLE ONLY "public"."matches"
    ADD CONSTRAINT "matches_team_a_fkey" FOREIGN KEY ("team_a") REFERENCES "public"."teams"("id");

ALTER TABLE ONLY "public"."matches"
    ADD CONSTRAINT "matches_team_b_fkey" FOREIGN KEY ("team_b") REFERENCES "public"."teams"("id");

ALTER TABLE ONLY "public"."password_resets"
    ADD CONSTRAINT "password_resets_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE CASCADE;

ALTER TABLE ONLY "public"."seasons"
    ADD CONSTRAINT "seasons_master_bracket_fk" FOREIGN KEY ("master_bracket_id") REFERENCES "public"."brackets"("id") ON DELETE SET NULL;

ALTER TABLE ONLY "public"."standings"
    ADD CONSTRAINT "standings_code_fkey" FOREIGN KEY ("code") REFERENCES "public"."teams"("code");

CREATE POLICY "Admins can manage all brackets" ON "public"."brackets" USING ((EXISTS ( SELECT 1
   FROM "public"."users" "u"
  WHERE (("u"."id" = "auth"."uid"()) AND ("u"."is_admin" = true)))));

CREATE POLICY "Admins can manage all matches" ON "public"."matches" USING ((EXISTS ( SELECT 1
   FROM "public"."users" "u"
  WHERE (("u"."id" = "auth"."uid"()) AND ("u"."is_admin" = true)))));

CREATE POLICY "Admins can manage all password resets" ON "public"."password_resets" USING ((EXISTS ( SELECT 1
   FROM "public"."users" "u"
  WHERE (("u"."id" = "auth"."uid"()) AND ("u"."is_admin" = true)))));

CREATE POLICY "Service role can manage all users" ON "public"."users" TO "service_role" USING (true) WITH CHECK (true);

CREATE POLICY "Users can delete matches of their own brackets" ON "public"."matches" FOR DELETE USING ((EXISTS ( SELECT 1
   FROM "public"."brackets" "b"
  WHERE (("b"."id" = "matches"."bracket_id") AND ("b"."user_id" = "auth"."uid"())))));

CREATE POLICY "Users can delete their own brackets" ON "public"."brackets" FOR DELETE USING (("auth"."uid"() = "user_id"));

CREATE POLICY "Users can insert matches of their own brackets" ON "public"."matches" FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."brackets" "b"
  WHERE (("b"."id" = "matches"."bracket_id") AND ("b"."user_id" = "auth"."uid"())))));

CREATE POLICY "Users can insert their own brackets" ON "public"."brackets" FOR INSERT WITH CHECK (("auth"."uid"() = "user_id"));

CREATE POLICY "Users can insert their own password resets" ON "public"."password_resets" WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."users" "u"
  WHERE (("u"."id" = "auth"."uid"()) AND ("u"."id" = "password_resets"."user_id")))));

CREATE POLICY "Users can update matches of their own brackets" ON "public"."matches" FOR UPDATE USING ((EXISTS ( SELECT 1
   FROM "public"."brackets" "b"
  WHERE (("b"."id" = "matches"."bracket_id") AND ("b"."user_id" = "auth"."uid"())))));

CREATE POLICY "Users can update their own brackets" ON "public"."brackets" FOR UPDATE USING (("auth"."uid"() = "user_id"));

CREATE POLICY "Users can update their own data" ON "public"."users" FOR UPDATE USING (("auth"."uid"() = "id")) WITH CHECK (("auth"."uid"() = "id"));

CREATE POLICY "Users can view matches of their own brackets" ON "public"."matches" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."brackets" "b"
  WHERE (("b"."id" = "matches"."bracket_id") AND ("b"."user_id" = "auth"."uid"())))));

CREATE POLICY "Users can view their own brackets" ON "public"."brackets" FOR SELECT USING (("auth"."uid"() = "user_id"));

CREATE POLICY "Users can view their own data" ON "public"."users" FOR SELECT USING (("auth"."uid"() = "id"));

CREATE POLICY "Users can view their own password resets" ON "public"."password_resets" USING ((EXISTS ( SELECT 1
   FROM "public"."users" "u"
  WHERE (("u"."id" = "auth"."uid"()) AND ("u"."id" = "password_resets"."user_id")))));

ALTER TABLE "public"."brackets" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."matches" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."password_resets" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."users" ENABLE ROW LEVEL SECURITY;

-- Current secured ACLs.
REVOKE ALL ON TABLE public.bracket_scores FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.bracket_scores TO postgres, service_role;
REVOKE ALL ON TABLE public.brackets FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.brackets TO postgres, service_role;
REVOKE ALL ON TABLE public.matches FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.matches TO postgres, service_role;
REVOKE ALL ON TABLE public.leaderboard_history FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.leaderboard_history TO postgres, service_role;
REVOKE ALL ON TABLE public.leaderboard_history_rows FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.leaderboard_history_rows TO postgres, service_role;
REVOKE ALL ON TABLE public.leaderboard_history_snapshots FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.leaderboard_history_snapshots TO postgres, service_role;
REVOKE ALL ON TABLE public.league_members FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.league_members TO postgres, service_role;
REVOKE ALL ON TABLE public.leagues FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.leagues TO postgres, service_role;
REVOKE ALL ON TABLE public.password_resets FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.password_resets TO postgres, service_role;
REVOKE ALL ON TABLE public.seasons FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.seasons TO postgres, service_role;
REVOKE ALL ON TABLE public.standings FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.standings TO postgres, service_role;
REVOKE ALL ON TABLE public.teams FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.teams TO postgres, service_role;
REVOKE ALL ON TABLE public.users FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.users TO postgres, service_role;
REVOKE ALL ON TABLE public.bracket_view FROM PUBLIC, anon, authenticated;
GRANT ALL ON TABLE public.bracket_view TO postgres, service_role;
REVOKE ALL ON SEQUENCE public.leaderboard_history_id_seq FROM PUBLIC, anon, authenticated;
GRANT ALL ON SEQUENCE public.leaderboard_history_id_seq TO postgres, service_role;
REVOKE ALL ON SEQUENCE public.password_resets_id_seq FROM PUBLIC, anon, authenticated;
GRANT ALL ON SEQUENCE public.password_resets_id_seq TO postgres, service_role;
REVOKE ALL ON SEQUENCE public.standings_id_seq FROM PUBLIC, anon, authenticated;
GRANT ALL ON SEQUENCE public.standings_id_seq TO postgres, service_role;
GRANT EXECUTE ON FUNCTION public._set_bracket_scores_season_id() TO PUBLIC, postgres, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public._set_matches_season_id() TO PUBLIC, postgres, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.atomic_update_match(uuid,text,text,integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.atomic_update_match(uuid,text,text,integer) TO postgres, service_role;
GRANT EXECUTE ON FUNCTION public.fix_season_master_on_bracket_soft_delete() TO PUBLIC, postgres, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.set_master_bracket(uuid,uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.set_master_bracket(uuid,uuid) TO postgres, service_role;
REVOKE ALL ON FUNCTION public.set_winner_atomic(uuid,text,integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.set_winner_atomic(uuid,text,integer) TO postgres, service_role;
REVOKE ALL ON FUNCTION public.undo_prediction_atomic(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.undo_prediction_atomic(uuid) TO postgres, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON TABLES TO postgres, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON SEQUENCES TO postgres, service_role;

DO $baseline_verify$
BEGIN
  IF (SELECT current_user) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: execution role';
  END IF;
  IF (SELECT current_setting('server_version_num')::integer >= 170000) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: PostgreSQL >=17; newer major needs review';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='postgres')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: role postgres';
  END IF;
  IF (SELECT has_schema_privilege('postgres','public','USAGE')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: public USAGE postgres';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: role anon';
  END IF;
  IF (SELECT has_schema_privilege('anon','public','USAGE')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: public USAGE anon';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: role authenticated';
  END IF;
  IF (SELECT has_schema_privilege('authenticated','public','USAGE')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: public USAGE authenticated';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='service_role')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: role service_role';
  END IF;
  IF (SELECT has_schema_privilege('service_role','public','USAGE')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: public USAGE service_role';
  END IF;
  IF (SELECT to_regnamespace('public') IS NOT NULL) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: schema public';
  END IF;
  IF (SELECT to_regnamespace('auth') IS NOT NULL) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: schema auth';
  END IF;
  IF (SELECT to_regnamespace('extensions') IS NOT NULL) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: schema extensions';
  END IF;
  IF (SELECT prorettype='uuid'::regtype FROM pg_proc WHERE oid=to_regprocedure('auth.uid()')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: platform function auth.uid()';
  END IF;
  IF (SELECT prorettype='uuid'::regtype FROM pg_proc WHERE oid=to_regprocedure('extensions.uuid_generate_v4()')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: platform function extensions.uuid_generate_v4()';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='plpgsql')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: extension plpgsql';
  END IF;
  IF (SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='uuid-ossp')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: extension uuid-ossp';
  END IF;
  IF (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE((SELECT defaclacl FROM pg_default_acl WHERE defaclrole='postgres'::regrole AND defaclnamespace=0 AND defaclobjtype='f'),acldefault('f','postgres'::regrole))) x) IS DISTINCT FROM 'PUBLIC:EXECUTE:false:postgres,postgres:EXECUTE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: unchanged supplied function defaults 0';
  END IF;
  IF (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE((SELECT defaclacl FROM pg_default_acl WHERE defaclrole='postgres'::regrole AND defaclnamespace='public'::regnamespace AND defaclobjtype='f'),ARRAY[]::aclitem[])) x) IS DISTINCT FROM 'anon:EXECUTE:false:postgres,authenticated:EXECUTE:false:postgres,postgres:EXECUTE:false:postgres,service_role:EXECUTE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: unchanged supplied function defaults ''public''::regnamespace';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p','v','m','S','f') AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid='pg_class'::regclass AND d.objid=c.oid AND d.deptype='e')) IS DISTINCT FROM 'bracket_scores,bracket_view,brackets,leaderboard_history,leaderboard_history_id_seq,leaderboard_history_rows,leaderboard_history_snapshots,league_members,leagues,matches,password_resets,password_resets_id_seq,seasons,standings,standings_id_seq,teams,users' THEN
    RAISE EXCEPTION 'Baseline mismatch: application relation inventory';
  END IF;
  IF (SELECT string_agg(p.proname, ',' ORDER BY p.proname COLLATE "C") FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')) IS DISTINCT FROM '_set_bracket_scores_season_id,_set_matches_season_id,atomic_update_match,fix_season_master_on_bracket_soft_delete,set_master_bracket,set_winner_atomic,undo_prediction_atomic' THEN
    RAISE EXCEPTION 'Baseline mismatch: application function inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.bracket_scores'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.bracket_scores'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'bracket_id,master_bracket_id,total_points,full_hits,partial_hits,misses,bonus_finalists,bonus_champion,points_by_round,points_by_match,updated_at,season_id' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bracket_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bracket_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bracket_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bracket_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='master_bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.master_bracket_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='master_bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.master_bracket_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='master_bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.master_bracket_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='master_bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.master_bracket_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.total_points type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.total_points nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.total_points default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.total_points identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.full_hits type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.full_hits nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.full_hits default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.full_hits identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.partial_hits type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.partial_hits nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.partial_hits default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.partial_hits identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.misses type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.misses nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.misses default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.misses identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bonus_finalists type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bonus_finalists nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bonus_finalists default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bonus_finalists identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bonus_champion type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bonus_champion nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bonus_champion default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.bonus_champion identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='points_by_round' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.points_by_round type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='points_by_round' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.points_by_round nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='points_by_round' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '''{}''::jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.points_by_round default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='points_by_round' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.points_by_round identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='points_by_match' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.points_by_match type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='points_by_match' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.points_by_match nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='points_by_match' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '''{}''::jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.points_by_match default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='points_by_match' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.points_by_match identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.updated_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.updated_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.updated_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.updated_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.season_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.season_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.season_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.bracket_scores'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores.season_id identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.bracket_scores'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.bracket_scores'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass) IS DISTINCT FROM 'bracket_scores_bonus_champion_check,bracket_scores_bonus_finalists_check,bracket_scores_bracket_id_fkey,bracket_scores_full_hits_check,bracket_scores_master_bracket_id_fkey,bracket_scores_misses_check,bracket_scores_partial_hits_check,bracket_scores_pkey,bracket_scores_season_id_fkey,bracket_scores_total_points_check' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.bracket_scores'::regclass) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.bracket_scores'::regclass AND NOT tgisinternal) IS DISTINCT FROM 'trg_bracket_scores_set_season' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.bracket_scores'::regclass) IS DISTINCT FROM 'bracket_scores_master_idx,bracket_scores_pkey,bracket_scores_total_points_idx,idx_bracket_scores_season_points' THEN
    RAISE EXCEPTION 'Baseline mismatch: bracket_scores index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.brackets'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.brackets'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,user_id,created_at,updated_at,is_done,saved_at,deleted_at,deleted_by_user_id,name,is_master,season_id' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.id nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.brackets'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'extensions.uuid_generate_v4()' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.user_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.user_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.brackets'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.user_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.user_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.created_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.created_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.brackets'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.created_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.created_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.updated_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.updated_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.brackets'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.updated_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.updated_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='is_done' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'boolean' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.is_done type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='is_done' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.is_done nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.brackets'::regclass AND a.attname='is_done' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'false' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.is_done default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='is_done' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.is_done identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='saved_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.saved_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='saved_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.saved_at nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.brackets'::regclass AND a.attname='saved_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.saved_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='saved_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.saved_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='deleted_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.deleted_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='deleted_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.deleted_at nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.brackets'::regclass AND a.attname='deleted_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.deleted_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='deleted_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.deleted_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='deleted_by_user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.deleted_by_user_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='deleted_by_user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.deleted_by_user_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.brackets'::regclass AND a.attname='deleted_by_user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.deleted_by_user_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='deleted_by_user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.deleted_by_user_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.name type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.name nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.brackets'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.name default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.name identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='is_master' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'boolean' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.is_master type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='is_master' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.is_master nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.brackets'::regclass AND a.attname='is_master' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'false' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.is_master default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='is_master' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.is_master identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.season_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.season_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.brackets'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.season_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.brackets'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets.season_id identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.brackets'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.brackets'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.brackets'::regclass) IS DISTINCT FROM 'brackets_pkey,brackets_season_id_fkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.brackets'::regclass) IS DISTINCT FROM 'Admins can manage all brackets,Users can delete their own brackets,Users can insert their own brackets,Users can update their own brackets,Users can view their own brackets' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.brackets'::regclass AND NOT tgisinternal) IS DISTINCT FROM 'trg_fix_season_master_on_bracket_soft_delete' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.brackets'::regclass) IS DISTINCT FROM 'brackets_pkey,idx_brackets_season_created,idx_brackets_user_id,uniq_active_bracket_per_user_per_season,unique_active_bracket_per_user,uq_master_per_season,ux_brackets_one_master_per_season' THEN
    RAISE EXCEPTION 'Baseline mismatch: brackets index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.matches'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.matches'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,bracket_id,round,slot,team_a,team_b,team_a_locked,team_b_locked,predicted_winner,predicted_winner_games,next_match_id,next_slot,created_at,updated_at,conference,season_id' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.id nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'extensions.uuid_generate_v4()' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.bracket_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.bracket_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.bracket_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.bracket_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='round' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.round type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='round' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.round nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='round' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.round default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='round' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.round identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='slot' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.slot type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='slot' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.slot nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='slot' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.slot default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='slot' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.slot identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_a' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_a type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_a' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_a nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='team_a' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_a default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_a' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_a identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_b' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_b type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_b' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_b nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='team_b' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_b default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_b' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_b identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_a_locked' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'boolean' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_a_locked type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_a_locked' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_a_locked nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='team_a_locked' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'false' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_a_locked default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_a_locked' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_a_locked identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_b_locked' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'boolean' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_b_locked type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_b_locked' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_b_locked nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='team_b_locked' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'false' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_b_locked default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='team_b_locked' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.team_b_locked identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='predicted_winner' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.predicted_winner type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='predicted_winner' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.predicted_winner nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='predicted_winner' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.predicted_winner default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='predicted_winner' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.predicted_winner identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='predicted_winner_games' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.predicted_winner_games type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='predicted_winner_games' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.predicted_winner_games nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='predicted_winner_games' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.predicted_winner_games default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='predicted_winner_games' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.predicted_winner_games identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='next_match_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.next_match_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='next_match_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.next_match_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='next_match_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.next_match_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='next_match_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.next_match_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='next_slot' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.next_slot type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='next_slot' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.next_slot nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='next_slot' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.next_slot default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='next_slot' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.next_slot identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.created_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.created_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.created_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.created_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.updated_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.updated_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.updated_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.updated_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.conference type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.conference nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '''East''::text' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.conference default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.conference identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.season_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.season_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.matches'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.season_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.matches'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches.season_id identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.matches'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: matches RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.matches'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: matches RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.matches'::regclass) IS DISTINCT FROM 'matches_bracket_id_fkey,matches_next_match_id_fkey,matches_next_slot_check,matches_pkey,matches_predicted_winner_fkey,matches_season_id_fkey,matches_team_a_fkey,matches_team_b_fkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.matches'::regclass) IS DISTINCT FROM 'Admins can manage all matches,Users can delete matches of their own brackets,Users can insert matches of their own brackets,Users can update matches of their own brackets,Users can view matches of their own brackets' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.matches'::regclass AND NOT tgisinternal) IS DISTINCT FROM 'trg_matches_set_season' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.matches'::regclass) IS DISTINCT FROM 'idx_matches_bracket,idx_matches_season_bracket,matches_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: matches index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.leaderboard_history'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.leaderboard_history'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,season_id,season_code,snapshot_at,rank,bracket_name,username,total_points,full_hits,partial_hits,misses,bonus_finalists,bonus_champion,points_by_match,bracket_id,user_id' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'bigint' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.id nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'nextval(''leaderboard_history_id_seq''::regclass)' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.season_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.season_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.season_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.season_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='season_code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.season_code type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='season_code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.season_code nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='season_code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.season_code default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='season_code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.season_code identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='snapshot_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.snapshot_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='snapshot_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.snapshot_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='snapshot_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.snapshot_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='snapshot_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.snapshot_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='rank' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.rank type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='rank' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.rank nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='rank' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.rank default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='rank' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.rank identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bracket_name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bracket_name type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bracket_name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bracket_name nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bracket_name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bracket_name default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bracket_name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bracket_name identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='username' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.username type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='username' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.username nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='username' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.username default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='username' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.username identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.total_points type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.total_points nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.total_points default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.total_points identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.full_hits type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.full_hits nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.full_hits default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.full_hits identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.partial_hits type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.partial_hits nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.partial_hits default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.partial_hits identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.misses type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.misses nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.misses default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.misses identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bonus_finalists type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bonus_finalists nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bonus_finalists default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bonus_finalists identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bonus_champion type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bonus_champion nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bonus_champion default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bonus_champion identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='points_by_match' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.points_by_match type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='points_by_match' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.points_by_match nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='points_by_match' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '''{}''::jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.points_by_match default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='points_by_match' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.points_by_match identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bracket_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bracket_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bracket_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.bracket_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.user_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.user_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.user_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history.user_id identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.leaderboard_history'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.leaderboard_history'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass) IS DISTINCT FROM 'leaderboard_history_bonus_champion_check,leaderboard_history_bonus_finalists_check,leaderboard_history_full_hits_check,leaderboard_history_misses_check,leaderboard_history_partial_hits_check,leaderboard_history_pkey,leaderboard_history_rank_check,leaderboard_history_season_id_fkey,leaderboard_history_total_points_check' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.leaderboard_history'::regclass) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.leaderboard_history'::regclass AND NOT tgisinternal) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.leaderboard_history'::regclass) IS DISTINCT FROM 'idx_leaderboard_history_season_rank,leaderboard_history_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.leaderboard_history_rows'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.leaderboard_history_rows'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,snapshot_id,rank,display_name,total_points,bonus_finalists,bonus_champion,full_hits,partial_hits,misses,per_match_points,created_at' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.id nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'extensions.uuid_generate_v4()' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='snapshot_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.snapshot_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='snapshot_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.snapshot_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='snapshot_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.snapshot_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='snapshot_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.snapshot_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='rank' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.rank type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='rank' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.rank nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='rank' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.rank default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='rank' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.rank identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='display_name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.display_name type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='display_name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.display_name nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='display_name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.display_name default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='display_name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.display_name identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.total_points type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.total_points nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.total_points default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='total_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.total_points identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.bonus_finalists type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.bonus_finalists nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.bonus_finalists default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='bonus_finalists' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.bonus_finalists identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.bonus_champion type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.bonus_champion nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.bonus_champion default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='bonus_champion' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.bonus_champion identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.full_hits type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.full_hits nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.full_hits default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='full_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.full_hits identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.partial_hits type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.partial_hits nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.partial_hits default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='partial_hits' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.partial_hits identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.misses type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.misses nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.misses default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='misses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.misses identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='per_match_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.per_match_points type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='per_match_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.per_match_points nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='per_match_points' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '''{}''::jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.per_match_points default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='per_match_points' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.per_match_points identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.created_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.created_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.created_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_rows'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows.created_at identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.leaderboard_history_rows'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.leaderboard_history_rows'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.leaderboard_history_rows'::regclass) IS DISTINCT FROM 'leaderboard_history_rows_pkey,leaderboard_history_rows_snapshot_id_fkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.leaderboard_history_rows'::regclass) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.leaderboard_history_rows'::regclass AND NOT tgisinternal) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.leaderboard_history_rows'::regclass) IS DISTINCT FROM 'idx_leaderboard_history_rows_snapshot,leaderboard_history_rows_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_rows index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.leaderboard_history_snapshots'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.leaderboard_history_snapshots'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,season_id,season_code,snapshot_at,columns,note,created_by,created_at' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.id nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'extensions.uuid_generate_v4()' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.season_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.season_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.season_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='season_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.season_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='season_code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.season_code type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='season_code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.season_code nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='season_code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.season_code default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='season_code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.season_code identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='snapshot_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.snapshot_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='snapshot_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.snapshot_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='snapshot_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.snapshot_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='snapshot_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.snapshot_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='columns' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.columns type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='columns' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.columns nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='columns' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '''[]''::jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.columns default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='columns' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.columns identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='note' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.note type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='note' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.note nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='note' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.note default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='note' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.note identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='created_by' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.created_by type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='created_by' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.created_by nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='created_by' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.created_by default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='created_by' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.created_by identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.created_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.created_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.created_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leaderboard_history_snapshots'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots.created_at identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.leaderboard_history_snapshots'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.leaderboard_history_snapshots'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.leaderboard_history_snapshots'::regclass) IS DISTINCT FROM 'leaderboard_history_snapshots_created_by_fkey,leaderboard_history_snapshots_pkey,leaderboard_history_snapshots_season_id_fkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.leaderboard_history_snapshots'::regclass) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.leaderboard_history_snapshots'::regclass AND NOT tgisinternal) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.leaderboard_history_snapshots'::regclass) IS DISTINCT FROM 'idx_leaderboard_history_snapshots_code,idx_leaderboard_history_snapshots_season,leaderboard_history_snapshots_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: leaderboard_history_snapshots index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.league_members'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.league_members'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,league_id,user_id,joined_at' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.id nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.league_members'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'extensions.uuid_generate_v4()' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='league_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.league_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='league_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.league_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.league_members'::regclass AND a.attname='league_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.league_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='league_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.league_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.user_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.user_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.league_members'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.user_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.user_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='joined_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.joined_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='joined_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.joined_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.league_members'::regclass AND a.attname='joined_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.joined_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.league_members'::regclass AND a.attname='joined_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members.joined_at identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.league_members'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.league_members'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.league_members'::regclass) IS DISTINCT FROM 'league_members_league_id_fkey,league_members_league_user_unique,league_members_pkey,league_members_user_id_fkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.league_members'::regclass) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.league_members'::regclass AND NOT tgisinternal) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.league_members'::regclass) IS DISTINCT FROM 'league_members_league_id_idx,league_members_league_user_unique,league_members_pkey,league_members_user_id_idx' THEN
    RAISE EXCEPTION 'Baseline mismatch: league_members index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.leagues'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.leagues'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,name,password_hash,owner_user_id,is_global,created_at,updated_at' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.id nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leagues'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'extensions.uuid_generate_v4()' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.name type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.name nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leagues'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.name default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.name identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='password_hash' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.password_hash type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='password_hash' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.password_hash nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leagues'::regclass AND a.attname='password_hash' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.password_hash default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='password_hash' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.password_hash identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='owner_user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.owner_user_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='owner_user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.owner_user_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leagues'::regclass AND a.attname='owner_user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.owner_user_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='owner_user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.owner_user_id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='is_global' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'boolean' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.is_global type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='is_global' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.is_global nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leagues'::regclass AND a.attname='is_global' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'false' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.is_global default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='is_global' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.is_global identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.created_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.created_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leagues'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.created_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.created_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.updated_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.updated_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.leagues'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.updated_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.leagues'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues.updated_at identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.leagues'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.leagues'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.leagues'::regclass) IS DISTINCT FROM 'leagues_name_unique,leagues_owner_user_id_fkey,leagues_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.leagues'::regclass) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.leagues'::regclass AND NOT tgisinternal) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.leagues'::regclass) IS DISTINCT FROM 'leagues_name_unique,leagues_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: leagues index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.password_resets'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.password_resets'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,token,expires_at,used,created_at,user_id' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.id nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.password_resets'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'nextval(''password_resets_id_seq''::regclass)' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='token' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.token type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='token' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.token nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.password_resets'::regclass AND a.attname='token' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.token default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='token' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.token identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='expires_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp without time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.expires_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='expires_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.expires_at nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.password_resets'::regclass AND a.attname='expires_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.expires_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='expires_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.expires_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='used' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'boolean' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.used type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='used' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.used nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.password_resets'::regclass AND a.attname='used' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'false' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.used default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='used' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.used identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp without time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.created_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.created_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.password_resets'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CURRENT_TIMESTAMP' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.created_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.created_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.user_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.user_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.password_resets'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.user_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.password_resets'::regclass AND a.attname='user_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets.user_id identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.password_resets'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.password_resets'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.password_resets'::regclass) IS DISTINCT FROM 'password_resets_pkey,password_resets_token_key,password_resets_user_id_fkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.password_resets'::regclass) IS DISTINCT FROM 'Admins can manage all password resets,Users can insert their own password resets,Users can view their own password resets' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.password_resets'::regclass AND NOT tgisinternal) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.password_resets'::regclass) IS DISTINCT FROM 'password_resets_pkey,password_resets_token_key' THEN
    RAISE EXCEPTION 'Baseline mismatch: password_resets index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.seasons'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.seasons'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,code,regular_season_end_utc,playoffs_start_utc,created_at,master_bracket_id' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.id nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.seasons'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'extensions.uuid_generate_v4()' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.code type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.code nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.seasons'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.code default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.code identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='regular_season_end_utc' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.regular_season_end_utc type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='regular_season_end_utc' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.regular_season_end_utc nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.seasons'::regclass AND a.attname='regular_season_end_utc' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.regular_season_end_utc default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='regular_season_end_utc' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.regular_season_end_utc identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='playoffs_start_utc' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.playoffs_start_utc type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='playoffs_start_utc' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.playoffs_start_utc nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.seasons'::regclass AND a.attname='playoffs_start_utc' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.playoffs_start_utc default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='playoffs_start_utc' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.playoffs_start_utc identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.created_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.created_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.seasons'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.created_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.created_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='master_bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.master_bracket_id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='master_bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.master_bracket_id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.seasons'::regclass AND a.attname='master_bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.master_bracket_id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.seasons'::regclass AND a.attname='master_bracket_id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons.master_bracket_id identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.seasons'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.seasons'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.seasons'::regclass) IS DISTINCT FROM 'seasons_code_key,seasons_master_bracket_fk,seasons_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.seasons'::regclass) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.seasons'::regclass AND NOT tgisinternal) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.seasons'::regclass) IS DISTINCT FROM 'seasons_code_key,seasons_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: seasons index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.standings'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.standings'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,name,code,wins,losses,conference,seed,updated_at,win_pct' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.id nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.standings'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'nextval(''standings_id_seq''::regclass)' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.name type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.name nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.standings'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.name default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.name identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.code type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.code nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.standings'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.code default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.code identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='wins' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.wins type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='wins' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.wins nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.standings'::regclass AND a.attname='wins' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.wins default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='wins' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.wins identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='losses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.losses type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='losses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.losses nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.standings'::regclass AND a.attname='losses' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '0' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.losses default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='losses' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.losses identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.conference type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.conference nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.standings'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.conference default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.conference identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='seed' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.seed type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='seed' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.seed nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.standings'::regclass AND a.attname='seed' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.seed default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='seed' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.seed identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp without time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.updated_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.updated_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.standings'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.updated_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='updated_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.updated_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='win_pct' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'double precision' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.win_pct type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='win_pct' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.win_pct nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.standings'::regclass AND a.attname='win_pct' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.win_pct default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.standings'::regclass AND a.attname='win_pct' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: standings.win_pct identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.standings'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: standings RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.standings'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: standings RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.standings'::regclass) IS DISTINCT FROM 'standings_code_fkey,standings_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.standings'::regclass) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.standings'::regclass AND NOT tgisinternal) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.standings'::regclass) IS DISTINCT FROM 'standings_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: standings index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.teams'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.teams'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,name,conference,code,logo_url,primary_color,secondary_color' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.id nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.teams'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.name type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.name nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.teams'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.name default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='name' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.name identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.conference type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.conference nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.teams'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.conference default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='conference' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.conference identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.code type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.code nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.teams'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.code default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='code' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.code identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='logo_url' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.logo_url type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='logo_url' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.logo_url nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.teams'::regclass AND a.attname='logo_url' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.logo_url default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='logo_url' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.logo_url identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='primary_color' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.primary_color type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='primary_color' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.primary_color nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.teams'::regclass AND a.attname='primary_color' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.primary_color default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='primary_color' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.primary_color identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='secondary_color' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.secondary_color type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='secondary_color' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.secondary_color nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.teams'::regclass AND a.attname='secondary_color' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.secondary_color default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.teams'::regclass AND a.attname='secondary_color' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: teams.secondary_color identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.teams'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: teams RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.teams'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: teams RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.teams'::regclass) IS DISTINCT FROM 'teams_code_key,teams_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.teams'::regclass) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.teams'::regclass AND NOT tgisinternal) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.teams'::regclass) IS DISTINCT FROM 'teams_code_key,teams_pkey' THEN
    RAISE EXCEPTION 'Baseline mismatch: teams index inventory';
  END IF;
  IF (SELECT relkind::text FROM pg_class WHERE oid='public.users'::regclass) IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: users kind';
  END IF;
  IF (SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.users'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM 'id,username,email,created_at,password,is_admin,reset_token,reset_token_expires' THEN
    RAISE EXCEPTION 'Baseline mismatch: users columns/order';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: users.id type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: users.id nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.users'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'extensions.uuid_generate_v4()' THEN
    RAISE EXCEPTION 'Baseline mismatch: users.id default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='id' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: users.id identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='username' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: users.username type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='username' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: users.username nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.users'::regclass AND a.attname='username' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: users.username default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='username' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: users.username identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='email' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: users.email type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='email' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: users.email nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.users'::regclass AND a.attname='email' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: users.email default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='email' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: users.email identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp with time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: users.created_at type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: users.created_at nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.users'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'now()' THEN
    RAISE EXCEPTION 'Baseline mismatch: users.created_at default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='created_at' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: users.created_at identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='password' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: users.password type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='password' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: users.password nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.users'::regclass AND a.attname='password' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: users.password default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='password' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: users.password identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='is_admin' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'boolean' THEN
    RAISE EXCEPTION 'Baseline mismatch: users.is_admin type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='is_admin' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: users.is_admin nullability';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.users'::regclass AND a.attname='is_admin' AND a.attnum>0 AND NOT a.attisdropped), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'false' THEN
    RAISE EXCEPTION 'Baseline mismatch: users.is_admin default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='is_admin' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: users.is_admin identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='reset_token' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'text' THEN
    RAISE EXCEPTION 'Baseline mismatch: users.reset_token type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='reset_token' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: users.reset_token nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.users'::regclass AND a.attname='reset_token' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: users.reset_token default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='reset_token' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: users.reset_token identity/generated/column ACL';
  END IF;
  IF (SELECT format_type(a.atttypid,a.atttypmod) FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='reset_token_expires' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM 'timestamp without time zone' THEN
    RAISE EXCEPTION 'Baseline mismatch: users.reset_token_expires type';
  END IF;
  IF (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='reset_token_expires' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: users.reset_token_expires nullability';
  END IF;
  IF (SELECT pg_get_expr(d.adbin,d.adrelid,true) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.users'::regclass AND a.attname='reset_token_expires' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: users.reset_token_expires default';
  END IF;
  IF (SELECT a.attidentity='' AND a.attgenerated='' AND a.attacl IS NULL FROM pg_attribute a WHERE a.attrelid='public.users'::regclass AND a.attname='reset_token_expires' AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: users.reset_token_expires identity/generated/column ACL';
  END IF;
  IF (SELECT relrowsecurity FROM pg_class WHERE oid='public.users'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: users RLS enabled';
  END IF;
  IF (SELECT relforcerowsecurity FROM pg_class WHERE oid='public.users'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: users RLS forced';
  END IF;
  IF (SELECT COALESCE(string_agg(conname, ',' ORDER BY conname COLLATE "C"),'') FROM pg_constraint WHERE conrelid='public.users'::regclass) IS DISTINCT FROM 'users_email_key,users_email_unique,users_pkey,users_username_unique' THEN
    RAISE EXCEPTION 'Baseline mismatch: users pg_constraint inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(polname, ',' ORDER BY polname COLLATE "C"),'') FROM pg_policy WHERE polrelid='public.users'::regclass) IS DISTINCT FROM 'Service role can manage all users,Users can update their own data,Users can view their own data' THEN
    RAISE EXCEPTION 'Baseline mismatch: users pg_policy inventory';
  END IF;
  IF (SELECT COALESCE(string_agg(tgname, ',' ORDER BY tgname COLLATE "C"),'') FROM pg_trigger WHERE tgrelid='public.users'::regclass AND NOT tgisinternal) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: users pg_trigger inventory';
  END IF;
  IF (SELECT string_agg(c.relname, ',' ORDER BY c.relname COLLATE "C") FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='public.users'::regclass) IS DISTINCT FROM 'users_email_key,users_email_unique,users_pkey,users_username_unique' THEN
    RAISE EXCEPTION 'Baseline mismatch: users index inventory';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_bonus_champion_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (bonus_champion >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint bracket_scores_bonus_champion_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_bonus_champion_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags bracket_scores_bonus_champion_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_bonus_finalists_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (bonus_finalists >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint bracket_scores_bonus_finalists_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_bonus_finalists_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags bracket_scores_bonus_finalists_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_bracket_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (bracket_id) REFERENCES brackets(id) ON DELETE CASCADE' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint bracket_scores_bracket_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_bracket_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags bracket_scores_bracket_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_full_hits_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (full_hits >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint bracket_scores_full_hits_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_full_hits_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags bracket_scores_full_hits_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_master_bracket_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (master_bracket_id) REFERENCES brackets(id) ON DELETE CASCADE' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint bracket_scores_master_bracket_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_master_bracket_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags bracket_scores_master_bracket_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_misses_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (misses >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint bracket_scores_misses_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_misses_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags bracket_scores_misses_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_partial_hits_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (partial_hits >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint bracket_scores_partial_hits_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_partial_hits_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags bracket_scores_partial_hits_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (bracket_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint bracket_scores_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags bracket_scores_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_season_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (season_id) REFERENCES seasons(id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint bracket_scores_season_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_season_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags bracket_scores_season_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_total_points_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (total_points >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint bracket_scores_total_points_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.bracket_scores'::regclass AND conname='bracket_scores_total_points_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags bracket_scores_total_points_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.brackets'::regclass AND conname='brackets_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint brackets_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.brackets'::regclass AND conname='brackets_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags brackets_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.brackets'::regclass AND conname='brackets_season_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (season_id) REFERENCES seasons(id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint brackets_season_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.brackets'::regclass AND conname='brackets_season_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags brackets_season_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_bonus_champion_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (bonus_champion >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_bonus_champion_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_bonus_champion_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_bonus_champion_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_bonus_finalists_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (bonus_finalists >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_bonus_finalists_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_bonus_finalists_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_bonus_finalists_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_full_hits_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (full_hits >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_full_hits_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_full_hits_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_full_hits_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_misses_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (misses >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_misses_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_misses_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_misses_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_partial_hits_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (partial_hits >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_partial_hits_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_partial_hits_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_partial_hits_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_rank_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (rank > 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_rank_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_rank_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_rank_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_season_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (season_id) REFERENCES seasons(id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_season_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_season_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_season_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_total_points_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (total_points >= 0)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_total_points_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history'::regclass AND conname='leaderboard_history_total_points_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_total_points_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history_rows'::regclass AND conname='leaderboard_history_rows_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_rows_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history_rows'::regclass AND conname='leaderboard_history_rows_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_rows_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history_rows'::regclass AND conname='leaderboard_history_rows_snapshot_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (snapshot_id) REFERENCES leaderboard_history_snapshots(id) ON DELETE CASCADE' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_rows_snapshot_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history_rows'::regclass AND conname='leaderboard_history_rows_snapshot_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_rows_snapshot_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history_snapshots'::regclass AND conname='leaderboard_history_snapshots_created_by_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (created_by) REFERENCES users(id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_snapshots_created_by_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history_snapshots'::regclass AND conname='leaderboard_history_snapshots_created_by_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_snapshots_created_by_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history_snapshots'::regclass AND conname='leaderboard_history_snapshots_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_snapshots_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history_snapshots'::regclass AND conname='leaderboard_history_snapshots_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_snapshots_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leaderboard_history_snapshots'::regclass AND conname='leaderboard_history_snapshots_season_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (season_id) REFERENCES seasons(id) ON DELETE CASCADE' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leaderboard_history_snapshots_season_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leaderboard_history_snapshots'::regclass AND conname='leaderboard_history_snapshots_season_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leaderboard_history_snapshots_season_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.league_members'::regclass AND conname='league_members_league_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (league_id) REFERENCES leagues(id) ON DELETE CASCADE' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint league_members_league_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.league_members'::regclass AND conname='league_members_league_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags league_members_league_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.league_members'::regclass AND conname='league_members_league_user_unique'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'UNIQUE (league_id, user_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint league_members_league_user_unique';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.league_members'::regclass AND conname='league_members_league_user_unique') IS DISTINCT FROM 'u:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags league_members_league_user_unique';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.league_members'::regclass AND conname='league_members_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint league_members_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.league_members'::regclass AND conname='league_members_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags league_members_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.league_members'::regclass AND conname='league_members_user_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint league_members_user_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.league_members'::regclass AND conname='league_members_user_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags league_members_user_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leagues'::regclass AND conname='leagues_name_unique'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'UNIQUE (name)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leagues_name_unique';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leagues'::regclass AND conname='leagues_name_unique') IS DISTINCT FROM 'u:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leagues_name_unique';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leagues'::regclass AND conname='leagues_owner_user_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (owner_user_id) REFERENCES users(id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leagues_owner_user_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leagues'::regclass AND conname='leagues_owner_user_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leagues_owner_user_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.leagues'::regclass AND conname='leagues_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint leagues_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.leagues'::regclass AND conname='leagues_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags leagues_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_bracket_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (bracket_id) REFERENCES brackets(id) ON DELETE CASCADE' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint matches_bracket_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_bracket_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags matches_bracket_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_next_match_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (next_match_id) REFERENCES matches(id) ON DELETE SET NULL' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint matches_next_match_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_next_match_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags matches_next_match_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_next_slot_check'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CHECK (next_slot = ANY (ARRAY[''a''::text, ''b''::text]))' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint matches_next_slot_check';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_next_slot_check') IS DISTINCT FROM 'c:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags matches_next_slot_check';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint matches_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags matches_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_predicted_winner_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (predicted_winner) REFERENCES teams(id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint matches_predicted_winner_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_predicted_winner_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags matches_predicted_winner_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_season_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (season_id) REFERENCES seasons(id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint matches_season_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_season_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags matches_season_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_team_a_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (team_a) REFERENCES teams(id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint matches_team_a_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_team_a_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags matches_team_a_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_team_b_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (team_b) REFERENCES teams(id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint matches_team_b_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.matches'::regclass AND conname='matches_team_b_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags matches_team_b_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.password_resets'::regclass AND conname='password_resets_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint password_resets_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.password_resets'::regclass AND conname='password_resets_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags password_resets_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.password_resets'::regclass AND conname='password_resets_token_key'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'UNIQUE (token)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint password_resets_token_key';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.password_resets'::regclass AND conname='password_resets_token_key') IS DISTINCT FROM 'u:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags password_resets_token_key';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.password_resets'::regclass AND conname='password_resets_user_id_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint password_resets_user_id_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.password_resets'::regclass AND conname='password_resets_user_id_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags password_resets_user_id_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.seasons'::regclass AND conname='seasons_code_key'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'UNIQUE (code)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint seasons_code_key';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.seasons'::regclass AND conname='seasons_code_key') IS DISTINCT FROM 'u:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags seasons_code_key';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.seasons'::regclass AND conname='seasons_master_bracket_fk'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (master_bracket_id) REFERENCES brackets(id) ON DELETE SET NULL' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint seasons_master_bracket_fk';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.seasons'::regclass AND conname='seasons_master_bracket_fk') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags seasons_master_bracket_fk';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.seasons'::regclass AND conname='seasons_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint seasons_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.seasons'::regclass AND conname='seasons_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags seasons_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.standings'::regclass AND conname='standings_code_fkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'FOREIGN KEY (code) REFERENCES teams(code)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint standings_code_fkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.standings'::regclass AND conname='standings_code_fkey') IS DISTINCT FROM 'f:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags standings_code_fkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.standings'::regclass AND conname='standings_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint standings_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.standings'::regclass AND conname='standings_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags standings_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.teams'::regclass AND conname='teams_code_key'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'UNIQUE (code)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint teams_code_key';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.teams'::regclass AND conname='teams_code_key') IS DISTINCT FROM 'u:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags teams_code_key';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.teams'::regclass AND conname='teams_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint teams_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.teams'::regclass AND conname='teams_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags teams_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.users'::regclass AND conname='users_email_key'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'UNIQUE (email)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint users_email_key';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.users'::regclass AND conname='users_email_key') IS DISTINCT FROM 'u:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags users_email_key';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.users'::regclass AND conname='users_email_unique'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'UNIQUE (email)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint users_email_unique';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.users'::regclass AND conname='users_email_unique') IS DISTINCT FROM 'u:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags users_email_unique';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.users'::regclass AND conname='users_pkey'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'PRIMARY KEY (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint users_pkey';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.users'::regclass AND conname='users_pkey') IS DISTINCT FROM 'p:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags users_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_constraintdef(oid,true) FROM pg_constraint WHERE conrelid='public.users'::regclass AND conname='users_username_unique'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'UNIQUE (username)' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint users_username_unique';
  END IF;
  IF (SELECT contype::text || ':' || condeferrable::text || ':' || condeferred::text || ':' || convalidated::text FROM pg_constraint WHERE conrelid='public.users'::regclass AND conname='users_username_unique') IS DISTINCT FROM 'u:false:false:true' THEN
    RAISE EXCEPTION 'Baseline mismatch: constraint flags users_username_unique';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.bracket_scores_master_idx'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX bracket_scores_master_idx ON bracket_scores USING btree (master_bracket_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index bracket_scores_master_idx';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.bracket_scores_master_idx'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready bracket_scores_master_idx';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.bracket_scores_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX bracket_scores_pkey ON bracket_scores USING btree (bracket_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index bracket_scores_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.bracket_scores_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready bracket_scores_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.bracket_scores_total_points_idx'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX bracket_scores_total_points_idx ON bracket_scores USING btree (total_points)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index bracket_scores_total_points_idx';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.bracket_scores_total_points_idx'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready bracket_scores_total_points_idx';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.idx_bracket_scores_season_points'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX idx_bracket_scores_season_points ON bracket_scores USING btree (season_id, total_points DESC)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index idx_bracket_scores_season_points';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.idx_bracket_scores_season_points'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready idx_bracket_scores_season_points';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.brackets_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX brackets_pkey ON brackets USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index brackets_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.brackets_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready brackets_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.idx_brackets_season_created'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX idx_brackets_season_created ON brackets USING btree (season_id, created_at DESC)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index idx_brackets_season_created';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.idx_brackets_season_created'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready idx_brackets_season_created';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.idx_brackets_user_id'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX idx_brackets_user_id ON brackets USING btree (user_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index idx_brackets_user_id';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.idx_brackets_user_id'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready idx_brackets_user_id';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.uniq_active_bracket_per_user_per_season'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX uniq_active_bracket_per_user_per_season ON brackets USING btree (user_id, season_id) WHERE (deleted_at IS NULL)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index uniq_active_bracket_per_user_per_season';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.uniq_active_bracket_per_user_per_season'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready uniq_active_bracket_per_user_per_season';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.unique_active_bracket_per_user'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX unique_active_bracket_per_user ON brackets USING btree (user_id) WHERE (deleted_at IS NULL)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index unique_active_bracket_per_user';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.unique_active_bracket_per_user'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready unique_active_bracket_per_user';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.uq_master_per_season'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX uq_master_per_season ON brackets USING btree (season_id) WHERE ((is_master IS TRUE) AND (deleted_at IS NULL))' THEN
    RAISE EXCEPTION 'Baseline mismatch: index uq_master_per_season';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.uq_master_per_season'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready uq_master_per_season';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.ux_brackets_one_master_per_season'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX ux_brackets_one_master_per_season ON brackets USING btree (season_id) WHERE (is_master = true)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index ux_brackets_one_master_per_season';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.ux_brackets_one_master_per_season'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready ux_brackets_one_master_per_season';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.idx_leaderboard_history_season_rank'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX idx_leaderboard_history_season_rank ON leaderboard_history USING btree (season_id, rank)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index idx_leaderboard_history_season_rank';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.idx_leaderboard_history_season_rank'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready idx_leaderboard_history_season_rank';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.leaderboard_history_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX leaderboard_history_pkey ON leaderboard_history USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index leaderboard_history_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.leaderboard_history_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready leaderboard_history_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.idx_leaderboard_history_rows_snapshot'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX idx_leaderboard_history_rows_snapshot ON leaderboard_history_rows USING btree (snapshot_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index idx_leaderboard_history_rows_snapshot';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.idx_leaderboard_history_rows_snapshot'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready idx_leaderboard_history_rows_snapshot';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.leaderboard_history_rows_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX leaderboard_history_rows_pkey ON leaderboard_history_rows USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index leaderboard_history_rows_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.leaderboard_history_rows_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready leaderboard_history_rows_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.idx_leaderboard_history_snapshots_code'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX idx_leaderboard_history_snapshots_code ON leaderboard_history_snapshots USING btree (season_code)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index idx_leaderboard_history_snapshots_code';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.idx_leaderboard_history_snapshots_code'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready idx_leaderboard_history_snapshots_code';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.idx_leaderboard_history_snapshots_season'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX idx_leaderboard_history_snapshots_season ON leaderboard_history_snapshots USING btree (season_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index idx_leaderboard_history_snapshots_season';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.idx_leaderboard_history_snapshots_season'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready idx_leaderboard_history_snapshots_season';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.leaderboard_history_snapshots_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX leaderboard_history_snapshots_pkey ON leaderboard_history_snapshots USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index leaderboard_history_snapshots_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.leaderboard_history_snapshots_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready leaderboard_history_snapshots_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.league_members_league_id_idx'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX league_members_league_id_idx ON league_members USING btree (league_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index league_members_league_id_idx';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.league_members_league_id_idx'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready league_members_league_id_idx';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.league_members_league_user_unique'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX league_members_league_user_unique ON league_members USING btree (league_id, user_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index league_members_league_user_unique';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.league_members_league_user_unique'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready league_members_league_user_unique';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.league_members_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX league_members_pkey ON league_members USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index league_members_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.league_members_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready league_members_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.league_members_user_id_idx'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX league_members_user_id_idx ON league_members USING btree (user_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index league_members_user_id_idx';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.league_members_user_id_idx'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready league_members_user_id_idx';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.leagues_name_unique'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX leagues_name_unique ON leagues USING btree (name)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index leagues_name_unique';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.leagues_name_unique'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready leagues_name_unique';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.leagues_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX leagues_pkey ON leagues USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index leagues_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.leagues_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready leagues_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.idx_matches_bracket'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX idx_matches_bracket ON matches USING btree (bracket_id, round)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index idx_matches_bracket';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.idx_matches_bracket'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready idx_matches_bracket';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.idx_matches_season_bracket'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE INDEX idx_matches_season_bracket ON matches USING btree (season_id, bracket_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index idx_matches_season_bracket';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.idx_matches_season_bracket'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready idx_matches_season_bracket';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.matches_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX matches_pkey ON matches USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index matches_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.matches_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready matches_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.password_resets_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX password_resets_pkey ON password_resets USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index password_resets_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.password_resets_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready password_resets_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.password_resets_token_key'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX password_resets_token_key ON password_resets USING btree (token)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index password_resets_token_key';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.password_resets_token_key'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready password_resets_token_key';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.seasons_code_key'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX seasons_code_key ON seasons USING btree (code)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index seasons_code_key';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.seasons_code_key'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready seasons_code_key';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.seasons_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX seasons_pkey ON seasons USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index seasons_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.seasons_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready seasons_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.standings_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX standings_pkey ON standings USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index standings_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.standings_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready standings_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.teams_code_key'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX teams_code_key ON teams USING btree (code)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index teams_code_key';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.teams_code_key'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready teams_code_key';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.teams_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX teams_pkey ON teams USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index teams_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.teams_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready teams_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.users_email_key'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX users_email_key ON users USING btree (email)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index users_email_key';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.users_email_key'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready users_email_key';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.users_email_unique'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX users_email_unique ON users USING btree (email)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index users_email_unique';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.users_email_unique'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready users_email_unique';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.users_pkey'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX users_pkey ON users USING btree (id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index users_pkey';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.users_pkey'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready users_pkey';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_indexdef('public.users_username_unique'::regclass)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE UNIQUE INDEX users_username_unique ON users USING btree (username)' THEN
    RAISE EXCEPTION 'Baseline mismatch: index users_username_unique';
  END IF;
  IF (SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='public.users_username_unique'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: index ready users_username_unique';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_triggerdef(oid,true) FROM pg_trigger WHERE tgrelid='public.bracket_scores'::regclass AND tgname='trg_bracket_scores_set_season' AND NOT tgisinternal), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE TRIGGER trg_bracket_scores_set_season BEFORE INSERT OR UPDATE OF bracket_id ON bracket_scores FOR EACH ROW EXECUTE FUNCTION _set_bracket_scores_season_id()' THEN
    RAISE EXCEPTION 'Baseline mismatch: trigger trg_bracket_scores_set_season';
  END IF;
  IF (SELECT tgenabled::text FROM pg_trigger WHERE tgrelid='public.bracket_scores'::regclass AND tgname='trg_bracket_scores_set_season' AND NOT tgisinternal) IS DISTINCT FROM 'O' THEN
    RAISE EXCEPTION 'Baseline mismatch: trigger enabled trg_bracket_scores_set_season';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_triggerdef(oid,true) FROM pg_trigger WHERE tgrelid='public.brackets'::regclass AND tgname='trg_fix_season_master_on_bracket_soft_delete' AND NOT tgisinternal), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE TRIGGER trg_fix_season_master_on_bracket_soft_delete BEFORE UPDATE ON brackets FOR EACH ROW EXECUTE FUNCTION fix_season_master_on_bracket_soft_delete()' THEN
    RAISE EXCEPTION 'Baseline mismatch: trigger trg_fix_season_master_on_bracket_soft_delete';
  END IF;
  IF (SELECT tgenabled::text FROM pg_trigger WHERE tgrelid='public.brackets'::regclass AND tgname='trg_fix_season_master_on_bracket_soft_delete' AND NOT tgisinternal) IS DISTINCT FROM 'O' THEN
    RAISE EXCEPTION 'Baseline mismatch: trigger enabled trg_fix_season_master_on_bracket_soft_delete';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_triggerdef(oid,true) FROM pg_trigger WHERE tgrelid='public.matches'::regclass AND tgname='trg_matches_set_season' AND NOT tgisinternal), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'CREATE TRIGGER trg_matches_set_season BEFORE INSERT OR UPDATE OF bracket_id ON matches FOR EACH ROW EXECUTE FUNCTION _set_matches_season_id()' THEN
    RAISE EXCEPTION 'Baseline mismatch: trigger trg_matches_set_season';
  END IF;
  IF (SELECT tgenabled::text FROM pg_trigger WHERE tgrelid='public.matches'::regclass AND tgname='trg_matches_set_season' AND NOT tgisinternal) IS DISTINCT FROM 'O' THEN
    RAISE EXCEPTION 'Baseline mismatch: trigger enabled trg_matches_set_season';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Admins can manage all brackets') IS DISTINCT FROM '*' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Admins can manage all brackets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Admins can manage all brackets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Admins can manage all brackets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.brackets'::regclass AND polname='Admins can manage all brackets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Admins can manage all brackets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Admins can manage all brackets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(EXISTS ( SELECT 1 FROM users u WHERE ((u.id = auth.uid()) AND (u.is_admin = true))))' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Admins can manage all brackets';
  END IF;
  IF (SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Admins can manage all brackets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Admins can manage all brackets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can delete their own brackets') IS DISTINCT FROM 'd' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can delete their own brackets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can delete their own brackets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can delete their own brackets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.brackets'::regclass AND polname='Users can delete their own brackets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can delete their own brackets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can delete their own brackets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(auth.uid() = user_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can delete their own brackets';
  END IF;
  IF (SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can delete their own brackets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can delete their own brackets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can insert their own brackets') IS DISTINCT FROM 'a' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can insert their own brackets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can insert their own brackets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can insert their own brackets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.brackets'::regclass AND polname='Users can insert their own brackets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can insert their own brackets';
  END IF;
  IF (SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can insert their own brackets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can insert their own brackets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can insert their own brackets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(auth.uid() = user_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can insert their own brackets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can update their own brackets') IS DISTINCT FROM 'w' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can update their own brackets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can update their own brackets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can update their own brackets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.brackets'::regclass AND polname='Users can update their own brackets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can update their own brackets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can update their own brackets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(auth.uid() = user_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can update their own brackets';
  END IF;
  IF (SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can update their own brackets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can update their own brackets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can view their own brackets') IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can view their own brackets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can view their own brackets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can view their own brackets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.brackets'::regclass AND polname='Users can view their own brackets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can view their own brackets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can view their own brackets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(auth.uid() = user_id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can view their own brackets';
  END IF;
  IF (SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.brackets'::regclass AND polname='Users can view their own brackets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can view their own brackets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Admins can manage all matches') IS DISTINCT FROM '*' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Admins can manage all matches';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Admins can manage all matches') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Admins can manage all matches';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.matches'::regclass AND polname='Admins can manage all matches') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Admins can manage all matches';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Admins can manage all matches'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(EXISTS ( SELECT 1 FROM users u WHERE ((u.id = auth.uid()) AND (u.is_admin = true))))' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Admins can manage all matches';
  END IF;
  IF (SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Admins can manage all matches') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Admins can manage all matches';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can delete matches of their own brackets') IS DISTINCT FROM 'd' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can delete matches of their own brackets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can delete matches of their own brackets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can delete matches of their own brackets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.matches'::regclass AND polname='Users can delete matches of their own brackets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can delete matches of their own brackets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can delete matches of their own brackets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(EXISTS ( SELECT 1 FROM brackets b WHERE ((b.id = matches.bracket_id) AND (b.user_id = auth.uid()))))' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can delete matches of their own brackets';
  END IF;
  IF (SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can delete matches of their own brackets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can delete matches of their own brackets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can insert matches of their own brackets') IS DISTINCT FROM 'a' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can insert matches of their own brackets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can insert matches of their own brackets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can insert matches of their own brackets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.matches'::regclass AND polname='Users can insert matches of their own brackets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can insert matches of their own brackets';
  END IF;
  IF (SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can insert matches of their own brackets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can insert matches of their own brackets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can insert matches of their own brackets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(EXISTS ( SELECT 1 FROM brackets b WHERE ((b.id = matches.bracket_id) AND (b.user_id = auth.uid()))))' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can insert matches of their own brackets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can update matches of their own brackets') IS DISTINCT FROM 'w' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can update matches of their own brackets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can update matches of their own brackets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can update matches of their own brackets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.matches'::regclass AND polname='Users can update matches of their own brackets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can update matches of their own brackets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can update matches of their own brackets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(EXISTS ( SELECT 1 FROM brackets b WHERE ((b.id = matches.bracket_id) AND (b.user_id = auth.uid()))))' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can update matches of their own brackets';
  END IF;
  IF (SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can update matches of their own brackets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can update matches of their own brackets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can view matches of their own brackets') IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can view matches of their own brackets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can view matches of their own brackets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can view matches of their own brackets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.matches'::regclass AND polname='Users can view matches of their own brackets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can view matches of their own brackets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can view matches of their own brackets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(EXISTS ( SELECT 1 FROM brackets b WHERE ((b.id = matches.bracket_id) AND (b.user_id = auth.uid()))))' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can view matches of their own brackets';
  END IF;
  IF (SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.matches'::regclass AND polname='Users can view matches of their own brackets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can view matches of their own brackets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Admins can manage all password resets') IS DISTINCT FROM '*' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Admins can manage all password resets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Admins can manage all password resets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Admins can manage all password resets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.password_resets'::regclass AND polname='Admins can manage all password resets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Admins can manage all password resets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Admins can manage all password resets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(EXISTS ( SELECT 1 FROM users u WHERE ((u.id = auth.uid()) AND (u.is_admin = true))))' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Admins can manage all password resets';
  END IF;
  IF (SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Admins can manage all password resets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Admins can manage all password resets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Users can insert their own password resets') IS DISTINCT FROM '*' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can insert their own password resets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Users can insert their own password resets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can insert their own password resets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.password_resets'::regclass AND polname='Users can insert their own password resets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can insert their own password resets';
  END IF;
  IF (SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Users can insert their own password resets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can insert their own password resets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Users can insert their own password resets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(EXISTS ( SELECT 1 FROM users u WHERE ((u.id = auth.uid()) AND (u.id = password_resets.user_id))))' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can insert their own password resets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Users can view their own password resets') IS DISTINCT FROM '*' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can view their own password resets';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Users can view their own password resets') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can view their own password resets';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.password_resets'::regclass AND polname='Users can view their own password resets') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can view their own password resets';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Users can view their own password resets'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(EXISTS ( SELECT 1 FROM users u WHERE ((u.id = auth.uid()) AND (u.id = password_resets.user_id))))' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can view their own password resets';
  END IF;
  IF (SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.password_resets'::regclass AND polname='Users can view their own password resets') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can view their own password resets';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Service role can manage all users') IS DISTINCT FROM '*' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Service role can manage all users';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Service role can manage all users') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Service role can manage all users';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.users'::regclass AND polname='Service role can manage all users') IS DISTINCT FROM 'service_role' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Service role can manage all users';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Service role can manage all users'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Service role can manage all users';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Service role can manage all users'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Service role can manage all users';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Users can update their own data') IS DISTINCT FROM 'w' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can update their own data';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Users can update their own data') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can update their own data';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.users'::regclass AND polname='Users can update their own data') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can update their own data';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Users can update their own data'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(auth.uid() = id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can update their own data';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Users can update their own data'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(auth.uid() = id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can update their own data';
  END IF;
  IF (SELECT polcmd::text FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Users can view their own data') IS DISTINCT FROM 'r' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy command Users can view their own data';
  END IF;
  IF (SELECT polpermissive FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Users can view their own data') IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: policy mode Users can view their own data';
  END IF;
  IF (SELECT string_agg(CASE WHEN rr=0 THEN 'public' ELSE pg_get_userbyid(rr) END, ',' ORDER BY rr) FROM pg_policy, unnest(polroles) rr WHERE polrelid='public.users'::regclass AND polname='Users can view their own data') IS DISTINCT FROM 'public' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy roles Users can view their own data';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_expr(polqual,polrelid,false) FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Users can view their own data'), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '(auth.uid() = id)' THEN
    RAISE EXCEPTION 'Baseline mismatch: policy using_expression Users can view their own data';
  END IF;
  IF (SELECT pg_get_expr(polwithcheck,polrelid,false) FROM pg_policy WHERE polrelid='public.users'::regclass AND polname='Users can view their own data') IS DISTINCT FROM NULL THEN
    RAISE EXCEPTION 'Baseline mismatch: policy with_check Users can view their own data';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_viewdef('public.bracket_view'::regclass,false)), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'SELECT m.id, m.bracket_id, m.round, m.slot, m.team_a, m.team_b, m.team_a_locked, m.team_b_locked, m.predicted_winner, m.predicted_winner_games, m.next_match_id, m.next_slot, m.created_at, m.updated_at, b.user_id FROM (matches m JOIN brackets b ON ((b.id = m.bracket_id)));' THEN
    RAISE EXCEPTION 'Baseline mismatch: view definition';
  END IF;
  IF (SELECT relkind='v' AND reloptions IS NULL AND NOT relrowsecurity AND NOT relforcerowsecurity FROM pg_class WHERE oid='public.bracket_view'::regclass) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: view options/security';
  END IF;
  IF (SELECT NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='public.bracket_view'::regclass AND attacl IS NOT NULL)) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: view column ACLs';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_identity_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_bracket_scores_season_id()')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_bracket_scores_season_id identity arguments';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_bracket_scores_season_id()')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_bracket_scores_season_id arguments/defaults';
  END IF;
  IF (SELECT pg_get_function_result(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_bracket_scores_season_id()')) IS DISTINCT FROM 'trigger' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_bracket_scores_season_id result';
  END IF;
  IF (SELECT p.prosecdef FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_bracket_scores_season_id()')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_bracket_scores_season_id security mode';
  END IF;
  IF (SELECT l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_bracket_scores_season_id()')) IS DISTINCT FROM 'plpgsql' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_bracket_scores_season_id language';
  END IF;
  IF (SELECT btrim(replace(p.prosrc,E'\r',''),E' \n\t') FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_bracket_scores_season_id()')) IS DISTINCT FROM 'BEGIN
  SELECT season_id INTO NEW.season_id FROM public.brackets WHERE id = NEW.bracket_id;
  RETURN NEW;
END' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_bracket_scores_season_id body';
  END IF;
  IF (SELECT p.proconfig IS NULL AND p.provolatile='v' AND NOT p.proisstrict AND p.proparallel='u' AND NOT p.proleakproof AND p.prokind='f' AND NOT p.proretset FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_bracket_scores_season_id()')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_bracket_scores_season_id settings';
  END IF;
  IF (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_bracket_scores_season_id()')) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_bracket_scores_season_id owner';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) x) FROM pg_proc p WHERE p.oid=to_regprocedure('public._set_bracket_scores_season_id()')) IS DISTINCT FROM 'PUBLIC:EXECUTE:false:postgres,anon:EXECUTE:false:postgres,authenticated:EXECUTE:false:postgres,postgres:EXECUTE:false:postgres,service_role:EXECUTE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function ACL _set_bracket_scores_season_id';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_identity_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_matches_season_id()')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_matches_season_id identity arguments';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_matches_season_id()')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_matches_season_id arguments/defaults';
  END IF;
  IF (SELECT pg_get_function_result(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_matches_season_id()')) IS DISTINCT FROM 'trigger' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_matches_season_id result';
  END IF;
  IF (SELECT p.prosecdef FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_matches_season_id()')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_matches_season_id security mode';
  END IF;
  IF (SELECT l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_matches_season_id()')) IS DISTINCT FROM 'plpgsql' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_matches_season_id language';
  END IF;
  IF (SELECT btrim(replace(p.prosrc,E'\r',''),E' \n\t') FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_matches_season_id()')) IS DISTINCT FROM 'BEGIN
  SELECT season_id INTO NEW.season_id FROM public.brackets WHERE id = NEW.bracket_id;
  RETURN NEW;
END' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_matches_season_id body';
  END IF;
  IF (SELECT p.proconfig IS NULL AND p.provolatile='v' AND NOT p.proisstrict AND p.proparallel='u' AND NOT p.proleakproof AND p.prokind='f' AND NOT p.proretset FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_matches_season_id()')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_matches_season_id settings';
  END IF;
  IF (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public._set_matches_season_id()')) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function _set_matches_season_id owner';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) x) FROM pg_proc p WHERE p.oid=to_regprocedure('public._set_matches_season_id()')) IS DISTINCT FROM 'PUBLIC:EXECUTE:false:postgres,anon:EXECUTE:false:postgres,authenticated:EXECUTE:false:postgres,postgres:EXECUTE:false:postgres,service_role:EXECUTE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function ACL _set_matches_season_id';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_identity_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.atomic_update_match(uuid,text,text,integer)')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'p_match_id uuid, p_action text, p_new_team text, p_games integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: function atomic_update_match identity arguments';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.atomic_update_match(uuid,text,text,integer)')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'p_match_id uuid, p_action text, p_new_team text DEFAULT NULL::text, p_games integer DEFAULT NULL::integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: function atomic_update_match arguments/defaults';
  END IF;
  IF (SELECT pg_get_function_result(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.atomic_update_match(uuid,text,text,integer)')) IS DISTINCT FROM 'json' THEN
    RAISE EXCEPTION 'Baseline mismatch: function atomic_update_match result';
  END IF;
  IF (SELECT p.prosecdef FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.atomic_update_match(uuid,text,text,integer)')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: function atomic_update_match security mode';
  END IF;
  IF (SELECT l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.atomic_update_match(uuid,text,text,integer)')) IS DISTINCT FROM 'plpgsql' THEN
    RAISE EXCEPTION 'Baseline mismatch: function atomic_update_match language';
  END IF;
  IF (SELECT btrim(replace(p.prosrc,E'\r',''),E' \n\t') FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.atomic_update_match(uuid,text,text,integer)')) IS DISTINCT FROM 'declare
  cur_match record;
  old_winner text;
  next_id uuid;
  nm record;
begin
  perform 1;
  -- load match
  select * into cur_match from matches where id = p_match_id;
  if cur_match is null then
    return json_build_object(''ok'', false, ''message'', ''match not found'');
  end if;

  if p_action = ''set_games'' then
    update matches set predicted_winner_games = p_games, updated_at = now() where id = p_match_id;
    return json_build_object(''ok'', true, ''message'', ''games updated'');
  elsif p_action = ''set_winner'' then
    if p_new_team is null then
      return json_build_object(''ok'', false, ''message'', ''missing p_new_team'');
    end if;

    old_winner := cur_match.predicted_winner;

    -- set this match''s winner & games
    update matches set predicted_winner = p_new_team,
                       predicted_winner_games = p_games,
                       updated_at = now()
    where id = p_match_id;

    -- clear descendants that involve old_winner (only if old_winner not null)
    if old_winner is not null and old_winner <> p_new_team then
      next_id := cur_match.next_match_id;
      while next_id is not null loop
        select * into nm from matches where id = next_id;
        exit when nm is null;

        -- if nm.predicted_winner == old_winner -> clear it
        if nm.predicted_winner = old_winner then
          update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now()
          where id = nm.id;
        end if;

        -- if team_a == old_winner and team_a not locked -> remove it
        if nm.team_a = old_winner and (nm.team_a_locked is distinct from true) then
          update matches set team_a = null, updated_at = now() where id = nm.id;
        end if;

        -- same for team_b
        if nm.team_b = old_winner and (nm.team_b_locked is distinct from true) then
          update matches set team_b = null, updated_at = now() where id = nm.id;
        end if;

        next_id := nm.next_match_id;
      end loop;
    end if;

    -- place new_team into immediate next_match slot (but do NOT set predicted_winner there)
    if cur_match.next_match_id is not null then
      select * into nm from matches where id = cur_match.next_match_id;
      if nm is not null then
        if cur_match.next_slot = ''a'' then
          if nm.team_a_locked is distinct from true then
            update matches set team_a = p_new_team, predicted_winner = null, predicted_winner_games = null, updated_at = now()
            where id = nm.id;
          end if;
        else
          if nm.team_b_locked is distinct from true then
            update matches set team_b = p_new_team, predicted_winner = null, predicted_winner_games = null, updated_at = now()
            where id = nm.id;
          end if;
        end if;
      end if;
    end if;

    return json_build_object(''ok'', true, ''message'', ''winner set'');
  elsif p_action = ''undo'' then
    old_winner := cur_match.predicted_winner;
    if old_winner is null then
      return json_build_object(''ok'', true, ''message'', ''nothing to undo'');
    end if;

    -- clear this match
    update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = p_match_id;

    -- clear propagated descendants and remove from slots (if not locked)
    next_id := cur_match.next_match_id;
    while next_id is not null loop
      select * into nm from matches where id = next_id;
      exit when nm is null;

      if nm.team_a = old_winner and (nm.team_a_locked is distinct from true) then
        update matches set team_a = null, updated_at = now() where id = nm.id;
      end if;
      if nm.team_b = old_winner and (nm.team_b_locked is distinct from true) then
        update matches set team_b = null, updated_at = now() where id = nm.id;
      end if;
      if nm.predicted_winner = old_winner then
        update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = nm.id;
      end if;

      next_id := nm.next_match_id;
    end loop;

    return json_build_object(''ok'', true, ''message'', ''undo complete'');
  else
    return json_build_object(''ok'', false, ''message'', ''invalid action'');
  end if;

end;' THEN
    RAISE EXCEPTION 'Baseline mismatch: function atomic_update_match body';
  END IF;
  IF (SELECT p.proconfig IS NULL AND p.provolatile='v' AND NOT p.proisstrict AND p.proparallel='u' AND NOT p.proleakproof AND p.prokind='f' AND NOT p.proretset FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.atomic_update_match(uuid,text,text,integer)')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: function atomic_update_match settings';
  END IF;
  IF (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.atomic_update_match(uuid,text,text,integer)')) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function atomic_update_match owner';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) x) FROM pg_proc p WHERE p.oid=to_regprocedure('public.atomic_update_match(uuid,text,text,integer)')) IS DISTINCT FROM 'postgres:EXECUTE:false:postgres,service_role:EXECUTE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function ACL atomic_update_match';
  END IF;
  IF (SELECT has_function_privilege('anon',to_regprocedure('public.atomic_update_match(uuid,text,text,integer)'),'EXECUTE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective RPC denied atomic_update_match anon';
  END IF;
  IF (SELECT has_function_privilege('authenticated',to_regprocedure('public.atomic_update_match(uuid,text,text,integer)'),'EXECUTE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective RPC denied atomic_update_match authenticated';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_identity_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.fix_season_master_on_bracket_soft_delete()')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: function fix_season_master_on_bracket_soft_delete identity arguments';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.fix_season_master_on_bracket_soft_delete()')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM '' THEN
    RAISE EXCEPTION 'Baseline mismatch: function fix_season_master_on_bracket_soft_delete arguments/defaults';
  END IF;
  IF (SELECT pg_get_function_result(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.fix_season_master_on_bracket_soft_delete()')) IS DISTINCT FROM 'trigger' THEN
    RAISE EXCEPTION 'Baseline mismatch: function fix_season_master_on_bracket_soft_delete result';
  END IF;
  IF (SELECT p.prosecdef FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.fix_season_master_on_bracket_soft_delete()')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: function fix_season_master_on_bracket_soft_delete security mode';
  END IF;
  IF (SELECT l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.fix_season_master_on_bracket_soft_delete()')) IS DISTINCT FROM 'plpgsql' THEN
    RAISE EXCEPTION 'Baseline mismatch: function fix_season_master_on_bracket_soft_delete language';
  END IF;
  IF (SELECT btrim(replace(p.prosrc,E'\r',''),E' \n\t') FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.fix_season_master_on_bracket_soft_delete()')) IS DISTINCT FROM 'BEGIN
  -- Act only on transition to soft-deleted
  IF TG_OP = ''UPDATE''
     AND NEW.deleted_at IS NOT NULL
     AND (OLD.deleted_at IS NULL OR OLD.deleted_at <> NEW.deleted_at) THEN

    -- Demote master flag on the row being updated (avoid recursive UPDATE by assigning NEW)
    IF NEW.is_master IS TRUE THEN
      NEW.is_master := FALSE;
    END IF;

    -- If the season points to this bracket, null it out
    UPDATE public.seasons
       SET master_bracket_id = NULL
     WHERE id = NEW.season_id
       AND master_bracket_id = NEW.id;
  END IF;

  RETURN NEW;
END' THEN
    RAISE EXCEPTION 'Baseline mismatch: function fix_season_master_on_bracket_soft_delete body';
  END IF;
  IF (SELECT p.proconfig IS NULL AND p.provolatile='v' AND NOT p.proisstrict AND p.proparallel='u' AND NOT p.proleakproof AND p.prokind='f' AND NOT p.proretset FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.fix_season_master_on_bracket_soft_delete()')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: function fix_season_master_on_bracket_soft_delete settings';
  END IF;
  IF (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.fix_season_master_on_bracket_soft_delete()')) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function fix_season_master_on_bracket_soft_delete owner';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) x) FROM pg_proc p WHERE p.oid=to_regprocedure('public.fix_season_master_on_bracket_soft_delete()')) IS DISTINCT FROM 'PUBLIC:EXECUTE:false:postgres,anon:EXECUTE:false:postgres,authenticated:EXECUTE:false:postgres,postgres:EXECUTE:false:postgres,service_role:EXECUTE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function ACL fix_season_master_on_bracket_soft_delete';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_identity_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_master_bracket(uuid,uuid)')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'season_id uuid, bracket_id uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_master_bracket identity arguments';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_master_bracket(uuid,uuid)')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'season_id uuid, bracket_id uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_master_bracket arguments/defaults';
  END IF;
  IF (SELECT pg_get_function_result(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_master_bracket(uuid,uuid)')) IS DISTINCT FROM 'void' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_master_bracket result';
  END IF;
  IF (SELECT p.prosecdef FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_master_bracket(uuid,uuid)')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_master_bracket security mode';
  END IF;
  IF (SELECT l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_master_bracket(uuid,uuid)')) IS DISTINCT FROM 'plpgsql' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_master_bracket language';
  END IF;
  IF (SELECT btrim(replace(p.prosrc,E'\r',''),E' \n\t') FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_master_bracket(uuid,uuid)')) IS DISTINCT FROM 'DECLARE
  prev_master uuid;
BEGIN
  -- Safety: make sure the bracket belongs to that season
  IF NOT EXISTS (
    SELECT 1 FROM public.brackets b
    WHERE b.id = bracket_id AND b.season_id = season_id
  ) THEN
    RAISE EXCEPTION ''Bracket % does not belong to season %'', bracket_id, season_id;
  END IF;

  -- Lock the season row to avoid races
  SELECT master_bracket_id
    INTO prev_master
  FROM public.seasons
  WHERE id = season_id
  FOR UPDATE;

  -- Demote prior master (if any)
  IF prev_master IS NOT NULL AND prev_master <> bracket_id THEN
    UPDATE public.brackets
    SET is_master = FALSE
    WHERE id = prev_master;
  END IF;

  -- Promote the new master
  UPDATE public.brackets
  SET is_master = TRUE
  WHERE id = bracket_id;

  -- Point season to the new master
  UPDATE public.seasons
  SET master_bracket_id = bracket_id
  WHERE id = season_id;
END;' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_master_bracket body';
  END IF;
  IF (SELECT p.proconfig IS NULL AND p.provolatile='v' AND NOT p.proisstrict AND p.proparallel='u' AND NOT p.proleakproof AND p.prokind='f' AND NOT p.proretset FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_master_bracket(uuid,uuid)')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_master_bracket settings';
  END IF;
  IF (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_master_bracket(uuid,uuid)')) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_master_bracket owner';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) x) FROM pg_proc p WHERE p.oid=to_regprocedure('public.set_master_bracket(uuid,uuid)')) IS DISTINCT FROM 'postgres:EXECUTE:false:postgres,service_role:EXECUTE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function ACL set_master_bracket';
  END IF;
  IF (SELECT has_function_privilege('anon',to_regprocedure('public.set_master_bracket(uuid,uuid)'),'EXECUTE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective RPC denied set_master_bracket anon';
  END IF;
  IF (SELECT has_function_privilege('authenticated',to_regprocedure('public.set_master_bracket(uuid,uuid)'),'EXECUTE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective RPC denied set_master_bracket authenticated';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_identity_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_winner_atomic(uuid,text,integer)')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'in_match uuid, in_new_team text, in_games integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_winner_atomic identity arguments';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_winner_atomic(uuid,text,integer)')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'in_match uuid, in_new_team text, in_games integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_winner_atomic arguments/defaults';
  END IF;
  IF (SELECT pg_get_function_result(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_winner_atomic(uuid,text,integer)')) IS DISTINCT FROM 'jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_winner_atomic result';
  END IF;
  IF (SELECT p.prosecdef FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_winner_atomic(uuid,text,integer)')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_winner_atomic security mode';
  END IF;
  IF (SELECT l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_winner_atomic(uuid,text,integer)')) IS DISTINCT FROM 'plpgsql' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_winner_atomic language';
  END IF;
  IF (SELECT btrim(replace(p.prosrc,E'\r',''),E' \n\t') FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_winner_atomic(uuid,text,integer)')) IS DISTINCT FROM 'declare
  start_row record;
  old_winner text;
  next_id uuid;
  nm record;
  cur_id uuid;
  affected_count integer := 0;
begin
  -- lock the starting match row
  select * into start_row from matches where id = in_match for update;
  if start_row is null then
    return jsonb_build_object(''ok'', false, ''error'', ''match_not_found'');
  end if;

  old_winner := start_row.predicted_winner;

  -- update this match with the new prediction
  update matches set predicted_winner = in_new_team,
                     predicted_winner_games = in_games,
                     updated_at = now()
    where id = in_match;

  affected_count := affected_count + 1;

  -- If there was an old winner, walk forward and clear it wherever it appears due to predictions
  cur_id := in_match;
  while true loop
    select next_match_id into next_id from matches where id = cur_id;
    if next_id is null then
      exit;
    end if;

    -- lock the child row
    select * into nm from matches where id = next_id for update;
    if nm is null then
      exit;
    end if;

    -- If nm.predicted_winner was the old_winner, clear it
    if old_winner is not null then
      if nm.predicted_winner = old_winner then
        update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = nm.id;
        affected_count := affected_count + 1;
      end if;

      -- If old_winner was placed into team_a or team_b (because it was advanced previously), clear that slot.
      if nm.team_a = old_winner then
        update matches set team_a = null, updated_at = now() where id = nm.id;
        affected_count := affected_count + 1;
      end if;
      if nm.team_b = old_winner then
        update matches set team_b = null, updated_at = now() where id = nm.id;
        affected_count := affected_count + 1;
      end if;
    end if;

    -- continue down the chain
    cur_id := nm.id;
  end loop;

  -- Place the new winner in the immediate next match slot (if exists), but keep predicted_winner null for that next match
  select next_match_id into next_id from matches where id = in_match;
  if next_id is not null then
    select * into nm from matches where id = next_id for update;
    if nm is not null then
      if (select next_slot from matches where id = in_match) = ''a'' then
        update matches set team_a = in_new_team, predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = nm.id;
      else
        update matches set team_b = in_new_team, predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = nm.id;
      end if;
      affected_count := affected_count + 1;
    end if;
  end if;

  return jsonb_build_object(''ok'', true, ''affected'', affected_count);
end;' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_winner_atomic body';
  END IF;
  IF (SELECT p.proconfig IS NULL AND p.provolatile='v' AND NOT p.proisstrict AND p.proparallel='u' AND NOT p.proleakproof AND p.prokind='f' AND NOT p.proretset FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_winner_atomic(uuid,text,integer)')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_winner_atomic settings';
  END IF;
  IF (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.set_winner_atomic(uuid,text,integer)')) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function set_winner_atomic owner';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) x) FROM pg_proc p WHERE p.oid=to_regprocedure('public.set_winner_atomic(uuid,text,integer)')) IS DISTINCT FROM 'postgres:EXECUTE:false:postgres,service_role:EXECUTE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function ACL set_winner_atomic';
  END IF;
  IF (SELECT has_function_privilege('anon',to_regprocedure('public.set_winner_atomic(uuid,text,integer)'),'EXECUTE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective RPC denied set_winner_atomic anon';
  END IF;
  IF (SELECT has_function_privilege('authenticated',to_regprocedure('public.set_winner_atomic(uuid,text,integer)'),'EXECUTE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective RPC denied set_winner_atomic authenticated';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_identity_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.undo_prediction_atomic(uuid)')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'in_match uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: function undo_prediction_atomic identity arguments';
  END IF;
  IF (btrim(regexp_replace(replace(replace((SELECT pg_get_function_arguments(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.undo_prediction_atomic(uuid)')), '"', ''), 'public.', ''), E'\\s+', ' ', 'g'))) IS DISTINCT FROM 'in_match uuid' THEN
    RAISE EXCEPTION 'Baseline mismatch: function undo_prediction_atomic arguments/defaults';
  END IF;
  IF (SELECT pg_get_function_result(p.oid) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.undo_prediction_atomic(uuid)')) IS DISTINCT FROM 'jsonb' THEN
    RAISE EXCEPTION 'Baseline mismatch: function undo_prediction_atomic result';
  END IF;
  IF (SELECT p.prosecdef FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.undo_prediction_atomic(uuid)')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: function undo_prediction_atomic security mode';
  END IF;
  IF (SELECT l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.undo_prediction_atomic(uuid)')) IS DISTINCT FROM 'plpgsql' THEN
    RAISE EXCEPTION 'Baseline mismatch: function undo_prediction_atomic language';
  END IF;
  IF (SELECT btrim(replace(p.prosrc,E'\r',''),E' \n\t') FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.undo_prediction_atomic(uuid)')) IS DISTINCT FROM 'declare
  start_row record;
  old_winner text;
  next_id uuid;
  nm record;
  cur_id uuid;
  affected_count integer := 0;
begin
  select * into start_row from matches where id = in_match for update;
  if start_row is null then
    return jsonb_build_object(''ok'', false, ''error'', ''match_not_found'');
  end if;

  old_winner := start_row.predicted_winner;

  -- clear this match
  update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = in_match;
  affected_count := affected_count + 1;

  -- walk forward and remove old_winner from slots and clear downstream predictions
  cur_id := in_match;
  while true loop
    select next_match_id into next_id from matches where id = cur_id;
    if next_id is null then
      exit;
    end if;

    select * into nm from matches where id = next_id for update;
    if nm is null then
      exit;
    end if;

    if nm.team_a = old_winner then
      update matches set team_a = null, updated_at = now() where id = nm.id;
      affected_count := affected_count + 1;
    end if;
    if nm.team_b = old_winner then
      update matches set team_b = null, updated_at = now() where id = nm.id;
      affected_count := affected_count + 1;
    end if;
    if nm.predicted_winner = old_winner then
      update matches set predicted_winner = null, predicted_winner_games = null, updated_at = now() where id = nm.id;
      affected_count := affected_count + 1;
    end if;

    cur_id := nm.id;
  end loop;

  return jsonb_build_object(''ok'', true, ''affected'', affected_count);
end;' THEN
    RAISE EXCEPTION 'Baseline mismatch: function undo_prediction_atomic body';
  END IF;
  IF (SELECT p.proconfig IS NULL AND p.provolatile='v' AND NOT p.proisstrict AND p.proparallel='u' AND NOT p.proleakproof AND p.prokind='f' AND NOT p.proretset FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.undo_prediction_atomic(uuid)')) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: function undo_prediction_atomic settings';
  END IF;
  IF (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('public.undo_prediction_atomic(uuid)')) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function undo_prediction_atomic owner';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) x) FROM pg_proc p WHERE p.oid=to_regprocedure('public.undo_prediction_atomic(uuid)')) IS DISTINCT FROM 'postgres:EXECUTE:false:postgres,service_role:EXECUTE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: function ACL undo_prediction_atomic';
  END IF;
  IF (SELECT has_function_privilege('anon',to_regprocedure('public.undo_prediction_atomic(uuid)'),'EXECUTE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective RPC denied undo_prediction_atomic anon';
  END IF;
  IF (SELECT has_function_privilege('authenticated',to_regprocedure('public.undo_prediction_atomic(uuid)'),'EXECUTE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective RPC denied undo_prediction_atomic authenticated';
  END IF;
  IF (SELECT seqstart FROM pg_sequence WHERE seqrelid='public.leaderboard_history_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence leaderboard_history_id_seq start';
  END IF;
  IF (SELECT seqincrement FROM pg_sequence WHERE seqrelid='public.leaderboard_history_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence leaderboard_history_id_seq increment';
  END IF;
  IF (SELECT seqmin FROM pg_sequence WHERE seqrelid='public.leaderboard_history_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence leaderboard_history_id_seq min';
  END IF;
  IF (SELECT seqmax FROM pg_sequence WHERE seqrelid='public.leaderboard_history_id_seq'::regclass) IS DISTINCT FROM 9223372036854775807 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence leaderboard_history_id_seq max';
  END IF;
  IF (SELECT seqcache FROM pg_sequence WHERE seqrelid='public.leaderboard_history_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence leaderboard_history_id_seq cache';
  END IF;
  IF (SELECT seqcycle FROM pg_sequence WHERE seqrelid='public.leaderboard_history_id_seq'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence leaderboard_history_id_seq cycle';
  END IF;
  IF (SELECT format_type(seqtypid,NULL) FROM pg_sequence WHERE seqrelid='public.leaderboard_history_id_seq'::regclass) IS DISTINCT FROM 'bigint' THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence leaderboard_history_id_seq type';
  END IF;
  IF (SELECT c.relname || '.' || a.attname FROM pg_depend d JOIN pg_class c ON c.oid=d.refobjid JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=d.refobjsubid WHERE d.classid='pg_class'::regclass AND d.objid='public.leaderboard_history_id_seq'::regclass AND d.refclassid='pg_class'::regclass AND d.deptype='a') IS DISTINCT FROM 'leaderboard_history.id' THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence leaderboard_history_id_seq ownership';
  END IF;
  IF (SELECT seqstart FROM pg_sequence WHERE seqrelid='public.password_resets_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence password_resets_id_seq start';
  END IF;
  IF (SELECT seqincrement FROM pg_sequence WHERE seqrelid='public.password_resets_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence password_resets_id_seq increment';
  END IF;
  IF (SELECT seqmin FROM pg_sequence WHERE seqrelid='public.password_resets_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence password_resets_id_seq min';
  END IF;
  IF (SELECT seqmax FROM pg_sequence WHERE seqrelid='public.password_resets_id_seq'::regclass) IS DISTINCT FROM 2147483647 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence password_resets_id_seq max';
  END IF;
  IF (SELECT seqcache FROM pg_sequence WHERE seqrelid='public.password_resets_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence password_resets_id_seq cache';
  END IF;
  IF (SELECT seqcycle FROM pg_sequence WHERE seqrelid='public.password_resets_id_seq'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence password_resets_id_seq cycle';
  END IF;
  IF (SELECT format_type(seqtypid,NULL) FROM pg_sequence WHERE seqrelid='public.password_resets_id_seq'::regclass) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence password_resets_id_seq type';
  END IF;
  IF (SELECT c.relname || '.' || a.attname FROM pg_depend d JOIN pg_class c ON c.oid=d.refobjid JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=d.refobjsubid WHERE d.classid='pg_class'::regclass AND d.objid='public.password_resets_id_seq'::regclass AND d.refclassid='pg_class'::regclass AND d.deptype='a') IS DISTINCT FROM 'password_resets.id' THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence password_resets_id_seq ownership';
  END IF;
  IF (SELECT seqstart FROM pg_sequence WHERE seqrelid='public.standings_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence standings_id_seq start';
  END IF;
  IF (SELECT seqincrement FROM pg_sequence WHERE seqrelid='public.standings_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence standings_id_seq increment';
  END IF;
  IF (SELECT seqmin FROM pg_sequence WHERE seqrelid='public.standings_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence standings_id_seq min';
  END IF;
  IF (SELECT seqmax FROM pg_sequence WHERE seqrelid='public.standings_id_seq'::regclass) IS DISTINCT FROM 2147483647 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence standings_id_seq max';
  END IF;
  IF (SELECT seqcache FROM pg_sequence WHERE seqrelid='public.standings_id_seq'::regclass) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence standings_id_seq cache';
  END IF;
  IF (SELECT seqcycle FROM pg_sequence WHERE seqrelid='public.standings_id_seq'::regclass) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence standings_id_seq cycle';
  END IF;
  IF (SELECT format_type(seqtypid,NULL) FROM pg_sequence WHERE seqrelid='public.standings_id_seq'::regclass) IS DISTINCT FROM 'integer' THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence standings_id_seq type';
  END IF;
  IF (SELECT c.relname || '.' || a.attname FROM pg_depend d JOIN pg_class c ON c.oid=d.refobjid JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=d.refobjsubid WHERE d.classid='pg_class'::regclass AND d.objid='public.standings_id_seq'::regclass AND d.refclassid='pg_class'::regclass AND d.deptype='a') IS DISTINCT FROM 'standings.id' THEN
    RAISE EXCEPTION 'Baseline mismatch: sequence standings_id_seq ownership';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.bracket_scores'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner bracket_scores';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.bracket_scores'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL bracket_scores';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_scores'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_scores'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_scores'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_scores'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_scores'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_scores'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_scores'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_scores'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.bracket_scores'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_scores anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.bracket_scores'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_scores anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.bracket_scores'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_scores anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.bracket_scores'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_scores anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_scores'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_scores'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_scores'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_scores'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_scores'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_scores'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_scores'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_scores'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_scores authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.bracket_scores'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_scores authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.bracket_scores'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_scores authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.bracket_scores'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_scores authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.bracket_scores'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_scores authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.bracket_view'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner bracket_view';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.bracket_view'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL bracket_view';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_view'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_view'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_view'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_view'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_view'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_view'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_view'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.bracket_view'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.bracket_view'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_view anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.bracket_view'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_view anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.bracket_view'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_view anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.bracket_view'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_view anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_view'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_view'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_view'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_view'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_view'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_view'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_view'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.bracket_view'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied bracket_view authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.bracket_view'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_view authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.bracket_view'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_view authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.bracket_view'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_view authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.bracket_view'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied bracket_view authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.brackets'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner brackets';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.brackets'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL brackets';
  END IF;
  IF (SELECT has_table_privilege('anon','public.brackets'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.brackets'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.brackets'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.brackets'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.brackets'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.brackets'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.brackets'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.brackets'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.brackets'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied brackets anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.brackets'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied brackets anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.brackets'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied brackets anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.brackets'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied brackets anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.brackets'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.brackets'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.brackets'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.brackets'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.brackets'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.brackets'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.brackets'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.brackets'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied brackets authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.brackets'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied brackets authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.brackets'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied brackets authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.brackets'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied brackets authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.brackets'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied brackets authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.leaderboard_history'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner leaderboard_history';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.leaderboard_history'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL leaderboard_history';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.leaderboard_history_id_seq'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner leaderboard_history_id_seq';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('s',relowner))) x) FROM pg_class WHERE oid='public.leaderboard_history_id_seq'::regclass) IS DISTINCT FROM 'postgres:SELECT:false:postgres,postgres:UPDATE:false:postgres,postgres:USAGE:false:postgres,service_role:SELECT:false:postgres,service_role:UPDATE:false:postgres,service_role:USAGE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL leaderboard_history_id_seq';
  END IF;
  IF (SELECT has_sequence_privilege('anon','public.leaderboard_history_id_seq'::regclass,'USAGE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_id_seq anon USAGE';
  END IF;
  IF (SELECT has_sequence_privilege('anon','public.leaderboard_history_id_seq'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_id_seq anon SELECT';
  END IF;
  IF (SELECT has_sequence_privilege('anon','public.leaderboard_history_id_seq'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_id_seq anon UPDATE';
  END IF;
  IF (SELECT has_sequence_privilege('authenticated','public.leaderboard_history_id_seq'::regclass,'USAGE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_id_seq authenticated USAGE';
  END IF;
  IF (SELECT has_sequence_privilege('authenticated','public.leaderboard_history_id_seq'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_id_seq authenticated SELECT';
  END IF;
  IF (SELECT has_sequence_privilege('authenticated','public.leaderboard_history_id_seq'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_id_seq authenticated UPDATE';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.leaderboard_history_rows'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner leaderboard_history_rows';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.leaderboard_history_rows'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL leaderboard_history_rows';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_rows'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_rows'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_rows'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_rows'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_rows'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_rows'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_rows'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_rows'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history_rows'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_rows anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history_rows'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_rows anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history_rows'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_rows anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history_rows'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_rows anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_rows'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_rows'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_rows'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_rows'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_rows'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_rows'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_rows'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_rows'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_rows authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history_rows'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_rows authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history_rows'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_rows authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history_rows'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_rows authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history_rows'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_rows authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.leaderboard_history_snapshots'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner leaderboard_history_snapshots';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.leaderboard_history_snapshots'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL leaderboard_history_snapshots';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_snapshots'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_snapshots'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_snapshots'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_snapshots'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_snapshots'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_snapshots'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_snapshots'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leaderboard_history_snapshots'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history_snapshots'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_snapshots anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history_snapshots'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_snapshots anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history_snapshots'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_snapshots anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leaderboard_history_snapshots'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_snapshots anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leaderboard_history_snapshots authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_snapshots authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_snapshots authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_snapshots authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leaderboard_history_snapshots'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leaderboard_history_snapshots authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.league_members'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner league_members';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.league_members'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL league_members';
  END IF;
  IF (SELECT has_table_privilege('anon','public.league_members'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.league_members'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.league_members'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.league_members'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.league_members'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.league_members'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.league_members'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.league_members'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.league_members'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied league_members anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.league_members'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied league_members anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.league_members'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied league_members anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.league_members'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied league_members anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.league_members'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.league_members'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.league_members'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.league_members'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.league_members'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.league_members'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.league_members'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.league_members'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied league_members authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.league_members'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied league_members authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.league_members'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied league_members authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.league_members'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied league_members authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.league_members'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied league_members authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.leagues'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner leagues';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.leagues'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL leagues';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leagues'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leagues'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leagues'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leagues'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leagues'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leagues'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leagues'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.leagues'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leagues'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leagues anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leagues'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leagues anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leagues'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leagues anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.leagues'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leagues anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leagues'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leagues'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leagues'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leagues'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leagues'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leagues'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leagues'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.leagues'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied leagues authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leagues'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leagues authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leagues'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leagues authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leagues'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leagues authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.leagues'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied leagues authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.matches'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner matches';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.matches'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL matches';
  END IF;
  IF (SELECT has_table_privilege('anon','public.matches'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.matches'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.matches'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.matches'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.matches'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.matches'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.matches'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.matches'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.matches'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied matches anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.matches'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied matches anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.matches'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied matches anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.matches'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied matches anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.matches'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.matches'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.matches'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.matches'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.matches'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.matches'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.matches'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.matches'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied matches authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.matches'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied matches authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.matches'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied matches authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.matches'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied matches authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.matches'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied matches authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.password_resets'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner password_resets';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.password_resets'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL password_resets';
  END IF;
  IF (SELECT has_table_privilege('anon','public.password_resets'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.password_resets'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.password_resets'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.password_resets'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.password_resets'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.password_resets'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.password_resets'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.password_resets'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.password_resets'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied password_resets anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.password_resets'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied password_resets anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.password_resets'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied password_resets anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.password_resets'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied password_resets anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.password_resets'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.password_resets'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.password_resets'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.password_resets'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.password_resets'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.password_resets'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.password_resets'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.password_resets'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.password_resets'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied password_resets authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.password_resets'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied password_resets authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.password_resets'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied password_resets authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.password_resets'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied password_resets authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.password_resets_id_seq'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner password_resets_id_seq';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('s',relowner))) x) FROM pg_class WHERE oid='public.password_resets_id_seq'::regclass) IS DISTINCT FROM 'postgres:SELECT:false:postgres,postgres:UPDATE:false:postgres,postgres:USAGE:false:postgres,service_role:SELECT:false:postgres,service_role:UPDATE:false:postgres,service_role:USAGE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL password_resets_id_seq';
  END IF;
  IF (SELECT has_sequence_privilege('anon','public.password_resets_id_seq'::regclass,'USAGE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets_id_seq anon USAGE';
  END IF;
  IF (SELECT has_sequence_privilege('anon','public.password_resets_id_seq'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets_id_seq anon SELECT';
  END IF;
  IF (SELECT has_sequence_privilege('anon','public.password_resets_id_seq'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets_id_seq anon UPDATE';
  END IF;
  IF (SELECT has_sequence_privilege('authenticated','public.password_resets_id_seq'::regclass,'USAGE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets_id_seq authenticated USAGE';
  END IF;
  IF (SELECT has_sequence_privilege('authenticated','public.password_resets_id_seq'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets_id_seq authenticated SELECT';
  END IF;
  IF (SELECT has_sequence_privilege('authenticated','public.password_resets_id_seq'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied password_resets_id_seq authenticated UPDATE';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.seasons'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner seasons';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.seasons'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL seasons';
  END IF;
  IF (SELECT has_table_privilege('anon','public.seasons'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.seasons'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.seasons'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.seasons'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.seasons'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.seasons'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.seasons'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.seasons'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.seasons'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied seasons anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.seasons'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied seasons anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.seasons'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied seasons anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.seasons'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied seasons anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.seasons'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.seasons'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.seasons'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.seasons'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.seasons'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.seasons'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.seasons'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.seasons'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied seasons authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.seasons'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied seasons authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.seasons'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied seasons authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.seasons'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied seasons authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.seasons'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied seasons authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.standings'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner standings';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.standings'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL standings';
  END IF;
  IF (SELECT has_table_privilege('anon','public.standings'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.standings'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.standings'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.standings'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.standings'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.standings'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.standings'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.standings'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.standings'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied standings anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.standings'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied standings anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.standings'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied standings anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.standings'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied standings anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.standings'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.standings'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.standings'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.standings'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.standings'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.standings'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.standings'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.standings'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.standings'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied standings authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.standings'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied standings authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.standings'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied standings authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.standings'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied standings authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.standings_id_seq'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner standings_id_seq';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('s',relowner))) x) FROM pg_class WHERE oid='public.standings_id_seq'::regclass) IS DISTINCT FROM 'postgres:SELECT:false:postgres,postgres:UPDATE:false:postgres,postgres:USAGE:false:postgres,service_role:SELECT:false:postgres,service_role:UPDATE:false:postgres,service_role:USAGE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL standings_id_seq';
  END IF;
  IF (SELECT has_sequence_privilege('anon','public.standings_id_seq'::regclass,'USAGE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings_id_seq anon USAGE';
  END IF;
  IF (SELECT has_sequence_privilege('anon','public.standings_id_seq'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings_id_seq anon SELECT';
  END IF;
  IF (SELECT has_sequence_privilege('anon','public.standings_id_seq'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings_id_seq anon UPDATE';
  END IF;
  IF (SELECT has_sequence_privilege('authenticated','public.standings_id_seq'::regclass,'USAGE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings_id_seq authenticated USAGE';
  END IF;
  IF (SELECT has_sequence_privilege('authenticated','public.standings_id_seq'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings_id_seq authenticated SELECT';
  END IF;
  IF (SELECT has_sequence_privilege('authenticated','public.standings_id_seq'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied standings_id_seq authenticated UPDATE';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.teams'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner teams';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.teams'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL teams';
  END IF;
  IF (SELECT has_table_privilege('anon','public.teams'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.teams'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.teams'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.teams'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.teams'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.teams'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.teams'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.teams'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.teams'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied teams anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.teams'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied teams anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.teams'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied teams anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.teams'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied teams anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.teams'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.teams'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.teams'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.teams'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.teams'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.teams'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.teams'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.teams'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied teams authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.teams'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied teams authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.teams'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied teams authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.teams'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied teams authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.teams'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied teams authenticated REFERENCES';
  END IF;
  IF (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.users'::regclass) IS DISTINCT FROM 'postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation owner users';
  END IF;
  IF (SELECT (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) x) FROM pg_class WHERE oid='public.users'::regclass) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: relation ACL users';
  END IF;
  IF (SELECT has_table_privilege('anon','public.users'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users anon SELECT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.users'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users anon INSERT';
  END IF;
  IF (SELECT has_table_privilege('anon','public.users'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users anon UPDATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.users'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users anon DELETE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.users'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users anon TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('anon','public.users'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('anon','public.users'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users anon TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('anon','public.users'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users anon MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.users'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied users anon SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.users'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied users anon INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.users'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied users anon UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('anon','public.users'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied users anon REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.users'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users authenticated SELECT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.users'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users authenticated INSERT';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.users'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users authenticated UPDATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.users'::regclass,'DELETE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users authenticated DELETE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.users'::regclass,'TRUNCATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users authenticated TRUNCATE';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.users'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users authenticated REFERENCES';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.users'::regclass,'TRIGGER')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users authenticated TRIGGER';
  END IF;
  IF (SELECT has_table_privilege('authenticated','public.users'::regclass,'MAINTAIN')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective denied users authenticated MAINTAIN';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.users'::regclass,'SELECT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied users authenticated SELECT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.users'::regclass,'INSERT')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied users authenticated INSERT';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.users'::regclass,'UPDATE')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied users authenticated UPDATE';
  END IF;
  IF (SELECT has_any_column_privilege('authenticated','public.users'::regclass,'REFERENCES')) IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'Baseline mismatch: effective columns denied users authenticated REFERENCES';
  END IF;
  IF (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE((SELECT defaclacl FROM pg_default_acl WHERE defaclrole='postgres'::regrole AND defaclnamespace='public'::regnamespace AND defaclobjtype='r'),ARRAY[]::aclitem[])) x) IS DISTINCT FROM 'postgres:DELETE:false:postgres,postgres:INSERT:false:postgres,postgres:MAINTAIN:false:postgres,postgres:REFERENCES:false:postgres,postgres:SELECT:false:postgres,postgres:TRIGGER:false:postgres,postgres:TRUNCATE:false:postgres,postgres:UPDATE:false:postgres,service_role:DELETE:false:postgres,service_role:INSERT:false:postgres,service_role:MAINTAIN:false:postgres,service_role:REFERENCES:false:postgres,service_role:SELECT:false:postgres,service_role:TRIGGER:false:postgres,service_role:TRUNCATE:false:postgres,service_role:UPDATE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: public default ACL r';
  END IF;
  IF (SELECT NOT EXISTS (SELECT 1 FROM aclexplode(COALESCE((SELECT defaclacl FROM pg_default_acl WHERE defaclrole='postgres'::regrole AND defaclnamespace=0 AND defaclobjtype='r'),acldefault('r','postgres'::regrole))) x WHERE x.grantee<>'postgres'::regrole OR x.is_grantable)) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: global defaults no extra recipients r';
  END IF;
  IF (SELECT string_agg(CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ':' || x.privilege_type || ':' || x.is_grantable::text || ':' || pg_get_userbyid(x.grantor), ',' ORDER BY (CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END) COLLATE "C", x.privilege_type COLLATE "C") FROM aclexplode(COALESCE((SELECT defaclacl FROM pg_default_acl WHERE defaclrole='postgres'::regrole AND defaclnamespace='public'::regnamespace AND defaclobjtype='S'),ARRAY[]::aclitem[])) x) IS DISTINCT FROM 'postgres:SELECT:false:postgres,postgres:UPDATE:false:postgres,postgres:USAGE:false:postgres,service_role:SELECT:false:postgres,service_role:UPDATE:false:postgres,service_role:USAGE:false:postgres' THEN
    RAISE EXCEPTION 'Baseline mismatch: public default ACL S';
  END IF;
  IF (SELECT NOT EXISTS (SELECT 1 FROM aclexplode(COALESCE((SELECT defaclacl FROM pg_default_acl WHERE defaclrole='postgres'::regrole AND defaclnamespace=0 AND defaclobjtype='S'),acldefault('s','postgres'::regrole))) x WHERE x.grantee<>'postgres'::regrole OR x.is_grantable)) IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'Baseline mismatch: global defaults no extra recipients S';
  END IF;
END
$baseline_verify$;
DO $platform_preservation$
BEGIN
  IF (SELECT md5(jsonb_build_object(
  'schemas',(SELECT jsonb_agg(jsonb_build_array(nspname,nspowner,nspacl) ORDER BY nspname) FROM pg_namespace),
  'roles',(SELECT jsonb_agg(jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls) ORDER BY rolname) FROM pg_roles),
  'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY roleid,member,grantor) FROM pg_auth_members m),
  'extensions',(SELECT jsonb_agg(jsonb_build_array(extname,extowner,extnamespace,extversion) ORDER BY extname) FROM pg_extension),
  'other_defaults',(SELECT jsonb_agg(to_jsonb(a) ORDER BY defaclrole,defaclnamespace,defaclobjtype) FROM pg_default_acl a
    WHERE NOT (defaclrole='postgres'::regrole AND defaclnamespace='public'::regnamespace AND defaclobjtype IN ('r','S')))
)::text)) IS DISTINCT FROM current_setting('nbacorner_baseline.platform_before') THEN
    RAISE EXCEPTION 'Out-of-scope platform metadata changed';
  END IF;
END
$platform_preservation$;
COMMIT;
