-- Load only into an empty, disposable test database. The HTTP role can only read.
CREATE ROLE fixture_reader NOLOGIN;
CREATE TABLE seasons (
    id int PRIMARY KEY, code text, master_bracket_id uuid,
    regular_season_end_utc timestamptz, playoffs_start_utc timestamptz
);
CREATE TABLE brackets (
    id uuid PRIMARY KEY, user_id int, is_done boolean, deleted_at timestamptz,
    name text, created_at timestamptz, saved_at timestamptz, is_master boolean DEFAULT false,
    season_id int CONSTRAINT brackets_season_id_fkey REFERENCES seasons(id)
);
ALTER TABLE seasons ADD CONSTRAINT seasons_master_bracket_fk
    FOREIGN KEY (master_bracket_id) REFERENCES brackets(id);
CREATE TABLE application_season (singleton boolean, season_id int);
CREATE TABLE leaderboard_history_snapshots (
    id int, season_id int, season_code text, snapshot_at timestamptz, columns jsonb, is_final boolean
);
CREATE TABLE leaderboard_history_rows (
    id int, snapshot_id int, rank int, display_name text, total_points int,
    bonus_finalists int, bonus_champion int, full_hits int, partial_hits int, misses int,
    per_match_points jsonb, saved_at timestamptz, base_points int, points_by_round jsonb, display_order int
);
CREATE TABLE leaderboard_history_competitors (snapshot_row_id int PRIMARY KEY, user_id int);
CREATE TABLE leaderboard_history (user_id int, bracket_id uuid, season_id int, season_code text);
CREATE TABLE matches (
    id int, bracket_id uuid, conference text, round int, slot int,
    team_a text, team_b text, predicted_winner text, predicted_winner_games int
);
CREATE TABLE teams (id text, name text, code text, logo_url text, primary_color text, secondary_color text);
CREATE TABLE users (id int, username text);

INSERT INTO seasons (id, code, regular_season_end_utc, playoffs_start_utc) VALUES
    (1, '2025-26', '2026-04-01Z', '2026-04-15Z'),
    (2, '2026-27', '2027-04-01Z', '2027-04-15Z'),
    (3, '2024-25', '2025-04-01Z', '2025-04-15Z'),
    (4, '2017-18', '2018-04-01Z', '2018-04-15Z');
INSERT INTO application_season VALUES (true, 2);
INSERT INTO leaderboard_history_snapshots
    SELECT id, id, code, now(), '[{"type":"summary","key":"full_hits","label":"Full hits"}]', true
    FROM seasons WHERE id <> 2;
INSERT INTO leaderboard_history_rows (id, snapshot_id, rank, display_name)
    SELECT s.id * 100 + i, s.id, i, s.season_code || ' entrant ' || i
    FROM leaderboard_history_snapshots s
    CROSS JOIN LATERAL generate_series(1, CASE WHEN s.id = 1 THEN 13 ELSE 22 END) i;
INSERT INTO brackets (id, season_id, user_id, is_done, name)
    SELECT lpad(to_hex(i), 32, '0')::uuid, 1, i, true, 'Archive bracket ' || i
    FROM generate_series(1,13) i;
INSERT INTO leaderboard_history_competitors SELECT 100 + user_id, user_id FROM brackets;
INSERT INTO leaderboard_history SELECT user_id, id, season_id, '2025-26' FROM brackets;
INSERT INTO matches
    SELECT row_number() OVER (), b.id, r.conf, r.round, slot, 'AAA', 'BBB', 'AAA', CASE WHEN r.round = 0 THEN 1 ELSE 4 END
    FROM brackets b CROSS JOIN (VALUES
        ('west',0,3), ('west',1,4), ('west',2,2), ('west',3,1),
        ('east',0,3), ('east',1,4), ('east',2,2), ('east',3,1), ('nba',4,1)
    ) r(conf,round,slots) CROSS JOIN LATERAL generate_series(1,r.slots) slot;
INSERT INTO teams (id, name, code) VALUES ('AAA', 'Team A', 'AAA'), ('BBB', 'Team B', 'BBB');
INSERT INTO brackets (id, season_id, user_id, is_done, deleted_at) VALUES
    ('00000000-0000-0000-0000-000000000014', 1, 20, false, NULL),
    ('00000000-0000-0000-0000-000000000015', 1, 21, true, now()),
    ('00000000-0000-0000-0000-000000000016', 2, 22, true, NULL);
GRANT USAGE ON SCHEMA public TO fixture_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO fixture_reader;
