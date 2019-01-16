import loader
import json


class TestLoader(object):

    def test_load_parse_hris(self):
        hris_data = {}
        with open('tests/fixtures/workday.json') as fd:
            hris_data = json.load(fd)

        hris = loader.hris_processor()
        profiles = hris.convert_hris_to_cis_profiles(hris_data)
        print("Parsed {} profiles".format(len(profiles)))
        print(profiles[0].as_json())
