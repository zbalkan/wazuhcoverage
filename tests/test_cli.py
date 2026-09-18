from wazuhcoverage.cli import build_parser


def test_cli_flags_and_targets() -> None:
    args = build_parser().parse_args(
        ["--ignore-history", "--no-stats", "/archives/**/*.json.gz", "/other/a.json.gz"]
    )

    assert args.ignore_history is True
    assert args.no_stats is True
    assert args.targets == ["/archives/**/*.json.gz", "/other/a.json.gz"]
