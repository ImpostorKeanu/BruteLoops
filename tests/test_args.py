import pytest
import bruteloops as BL

def test_timezone_parser():

    # Valid timezone
    BL.args.timezone_parser.parse_args(['-tz', 'EST'])

    # Invalid timezone
    with pytest.raises(ValueError):
        BL.args.timezone_parser.parse_args(['-tz', 'INVALID'])

def test_general_parser():

    def parse(args):
        BL.args.general_parser.parse_args(args)

    # ===============
    # BLACKOUT WINDOW
    # ===============

    # BlackoutModel window
    bw_args = ['--blackout-window', '17:00:00-09:00:00']
    parse(bw_args)

    orig = bw_args.pop()

    # Extra dash
    bw_args.append(orig+'-')
    with pytest.raises(ValueError):
        parse(bw_args)

    # Invalid time format
    bw_args.pop()
    bw_args.append(orig[:-3])

    with pytest.raises(ValueError):
        parse(bw_args)
