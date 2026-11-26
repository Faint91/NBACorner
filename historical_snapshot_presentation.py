"""Read-only presentation metadata for exact frozen historical snapshots."""

# The 2025-26 snapshot's archived master was verified against the October 18
# backup manifest. The coordinate, team order and names come from that backup.
_TEAM_LABELS = {
    "east-0-1": ("Charlotte Hornets vs. Miami Heat", "CHA \u2013 MIA"),
    "east-0-2": ("Philadelphia 76ers vs. Orlando Magic", "PHI \u2013 ORL"),
    "east-0-3": ("Charlotte Hornets vs. Orlando Magic", "CHA \u2013 ORL"),
    "west-0-1": ("Los Angeles Clippers vs. Golden State Warriors", "LAC \u2013 GSW"),
    "west-0-2": ("Phoenix Suns vs. Portland Trail Blazers", "PHX \u2013 POR"),
    "west-0-3": ("Golden State Warriors vs. Phoenix Suns", "GSW \u2013 PHX"),
    "east-1-4": ("Detroit Pistons vs. Orlando Magic", "DET \u2013 ORL"),
    "east-1-5": ("Boston Celtics vs. Philadelphia 76ers", "BOS \u2013 PHI"),
    "east-1-6": ("New York Knicks vs. Atlanta Hawks", "NYK \u2013 ATL"),
    "east-1-7": ("Cleveland Cavaliers vs. Toronto Raptors", "CLE \u2013 TOR"),
    "west-1-4": ("Oklahoma City Thunder vs. Phoenix Suns", "OKC \u2013 PHX"),
    "west-1-5": ("San Antonio Spurs vs. Portland Trail Blazers", "SAS \u2013 POR"),
    "west-1-6": ("Denver Nuggets vs. Minnesota Timberwolves", "DEN \u2013 MIN"),
    "west-1-7": ("Los Angeles Lakers vs. Houston Rockets", "LAL \u2013 HOU"),
    "east-2-8": ("New York Knicks vs. Philadelphia 76ers", "NYK \u2013 PHI"),
    "east-2-9": ("Detroit Pistons vs. Cleveland Cavaliers", "DET \u2013 CLE"),
    "west-2-8": ("Minnesota Timberwolves vs. San Antonio Spurs", "MIN \u2013 SAS"),
    "west-2-9": ("Oklahoma City Thunder vs. Los Angeles Lakers", "OKC \u2013 LAL"),
    "east-3-10": ("Cleveland Cavaliers vs. New York Knicks", "CLE \u2013 NYK"),
    "west-3-10": ("Oklahoma City Thunder vs. San Antonio Spurs", "OKC \u2013 SAS"),
    "nba-4-11": ("New York Knicks vs. San Antonio Spurs", "NYK \u2013 SAS"),
}
_TEAM_LABEL_SNAPSHOT = ("2025-26", "1df7e788-9e5a-4b5e-9cd5-1d65eae9916b")

# Each key was verified against the stored columns and every numeric score row.
_LEGACY_KEYS = {
    ("2017-18", "7812e982-1e70-4cb4-a775-c2321cf2a3a5"): frozenset((
        "tor_was", "cle_ind", "phi_mia", "bos_mil", "hou_min",
        "uta_okc", "por_nop", "gsw_sas", "tor_cle", "bos_phi",
        "hou_uta", "gsw_nop", "bos_cle", "hou_gsw", "cle_gsw",
    )),
    ("2018-19", "a06cad70-f2d1-4ff9-8a13-3e836d0fb26c"): frozenset((
        "gsw_lac", "hou_uta", "por_okc", "den_sas", "mil_det",
        "tor_orl", "phi_bkn", "bos_ind", "gsw_hou", "por_den",
        "mil_bos", "tor_phi", "gsw_por", "mil_tor", "gsw_tor",
    )),
    ("2019-20", "8fe9031f-c5d2-4517-9dd7-38bc4ff09a5f"): frozenset((
        "lal_por", "okc_hou", "den_uta", "lac_dal", "mil_orl",
        "mia_ind", "bos_phi", "tor_bkn", "lal_hou", "den_lac",
        "mil_mia", "bos_tor", "lal_den", "bos_mia", "lal_mia",
    )),
    ("2020-21", "2666b16a-48e6-4ddd-9e64-7d03d81895cc"): frozenset((
        "uta_mem", "lac_dal", "den_por", "phx_lal", "phi_was",
        "nyk_atl", "mil_mia", "bkn_bos", "phi_atl", "mil_bkn",
        "den_phx", "lac_uta", "phx_lac", "atl_mil", "phx_mil",
    )),
    ("2021-22", "76de48b4-7de5-4b99-9329-88d99410cbb9"): frozenset((
        "mia_atl", "phi_tor", "mil_chi", "bos_bkn", "phx_nop",
        "dal_uta", "gsw_den", "mem_min", "mia_phi", "mil_bos",
        "phx_dal", "gsw_mem", "mia_bos", "gsw_dal", "bos_gsw",
    )),
    ("2022-23", "15c1d0a2-0cd3-4456-b723-df83fdb5aaaf"): frozenset((
        "den_min", "phx_lac", "sac_gsw", "mem_lal", "mil_mia",
        "cle_nyk", "phi_bkn", "bos_atl", "den_phx", "gsw_lal",
        "mia_nyk", "phi_bos", "den_lal", "bos_mia", "den_mia",
    )),
    ("2024-25", "ef9daf28-7294-49fc-9a67-ee074c8ad242"): frozenset((
        "okc_mem", "den_lac", "lal_min", "hou_gsw", "cle_mia",
        "ind_mil", "nyk_det", "bos_orl", "okc_den", "min_gsw",
        "cle_ind", "bos_nyk", "okc_min", "nyk_ind", "okc_ind",
    )),
}


def presentation_for(snapshot):
    """Return only metadata approved for this exact season and snapshot ID."""
    snapshot = snapshot or {}
    key = (snapshot.get("season_code"), snapshot.get("id"))
    return _LEGACY_KEYS.get(key, frozenset()), _TEAM_LABELS if key == _TEAM_LABEL_SNAPSHOT else {}
