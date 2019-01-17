import loader
import json
from os import getenv


class TestLoader(object):

    def test_load_parse_hris(self):
        hris_data = {}
        with open('tests/fixtures/workday.json') as fd:
            hris_data = json.load(fd)

        hris = loader.hris_processor(getenv('CIS_ENVIRONMENT', 'development'))
        profiles = hris.convert_hris_to_cis_profiles(hris_data)
        print("Parsed {} profiles".format(len(profiles)))
        c = 0
        for p in profiles:
            assert p.first_name.value is not None
            if hris_data['Report_Entry'][c]['IsManager'] == 'TRUE':
                assert p.staff_information.manager.value is True
            else:
                assert p.staff_information.manager.value is False

            # Just info for debugging
            d = p.as_dict()
            si = {}
            for i in d['staff_information']:
                si[i] = d['staff_information'][i]['value']
            print(p.first_name.value, p.last_name.value, d['access_information']['hris']['values'],
                  si)
            c = c + 1
