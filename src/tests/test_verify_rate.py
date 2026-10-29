from verify_rate import parse_capture, peak_rate


def test_parse_capture_extracts_destination_and_timestamp():
    output = (
        "1.25 eth0 Out IP 172.28.0.2.53000 > 172.28.0.101.53: 1+ [1au] A?\n"
        "2.50 eth0 Out IP 172.28.0.2.53001 > 172.28.0.102.53: 2+ SOA?\n"
        "2.60 eth0 Out IP 172.28.0.2.53001 > 172.28.0.102.53: Flags [S]\n"
        "listening on any, link-type LINUX_SLL2\n"
    )

    assert parse_capture(output) == {
        "172.28.0.101": [1.25],
        "172.28.0.102": [2.5],
    }


def test_peak_rate_uses_sliding_one_second_window():
    assert peak_rate([0.0, 0.1, 0.9, 1.0, 1.1]) == 3
    assert peak_rate([0.0, 1.0, 2.0]) == 1


def test_stability_command_parser_defaults_to_three_runs():
    from dnsassess.cli import build_parser

    args = build_parser().parse_args(
        [
            "verify-stability",
            "--scope",
            "scope.yaml",
            "--rate",
            "rate.yaml",
        ]
    )

    assert args.runs == 3
