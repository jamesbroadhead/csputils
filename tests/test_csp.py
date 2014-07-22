#pylint: disable=line-too-long

import unittest

from csputils import CSP

class Fixtures(object):
    one = {
        'str' : "default-src 'self'; object-src 'self' https://www.youtube.com; script-src 'self' 'unsafe-eval' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://api-ssl.bitly.com; report-uri https://twitter.com/scribes/csp_report",

        'obj' : CSP({
            'default-src' : CSP.SELF,
            'object-src'  : [CSP.SELF, 'https://www.youtube.com'],
            'script-src'  : [CSP.SELF, CSP.UNSAFE_EVAL, 'https://*.twitter.com',
                             'https://*.twimg.com', 'https://ssl.google-analytics.com',
                             'https://api-ssl.bitly.com'],
            'report-uri'  : 'https://twitter.com/scribes/csp_report' })
    }

    two = {
        'str' : "allow 'self'; object-src 'self' https://www.youtube.com; options eval-script; script-src 'self' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://api-ssl.bitly.com; report-uri /csp_report",

        'obj' : CSP({
            'allow'      : CSP.SELF,
            'options'    : 'eval-script',
            'object-src' : [CSP.SELF, 'https://www.youtube.com'],
            'script-src' : [CSP.SELF, 'https://*.twitter.com', 'https://*.twimg.com',
                            'https://ssl.google-analytics.com', 'https://api-ssl.bitly.com'],
            'report-uri' : '/csp_report'
            })
    }


    three = {
        'str' : "object-src 'self' https://www.youtube.com; script-src 'self' 'unsafe-eval' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://graph.facebook.com https://api-read.facebook.com https://api-ssl.bitly.com; report-uri https://twitter.com/scribes/csp_report",

        'obj' : CSP({
            'object-src' : [CSP.SELF, 'https://www.youtube.com'],
            'script-src' : [CSP.SELF, CSP.UNSAFE_EVAL, 'https://*.twitter.com',
                            'https://*.twimg.com', 'https://ssl.google-analytics.com',
                            'https://graph.facebook.com', 'https://api-read.facebook.com',
                            'https://api-ssl.bitly.com'],
            'report-uri' : 'https://twitter.com/scribes/csp_report' })
    }


    four = {
        'str' : "object-src 'self' https://www.youtube.com; options eval-script; script-src 'self' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://graph.facebook.com https://api-read.facebook.com https://api-ssl.bitly.com; report-uri /csp_report",

        'obj' : CSP({
                'options'    : 'eval-script',
                'object-src' : [CSP.SELF, 'https://www.youtube.com'],
                'script-src' : [CSP.SELF, 'https://*.twitter.com', 'https://*.twimg.com',
                                'https://ssl.google-analytics.com',
                                'https://graph.facebook.com', 'https://api-read.facebook.com',
                                'https://api-ssl.bitly.com'],
                'report-uri' :  '/csp_report' })
    }


class TestCSP(unittest.TestCase):

    def test_equivalence(self):

        for fixture in [ Fixtures.one, Fixtures.two, Fixtures.three, Fixtures.four ]:
            self.assertEqual(str(fixture['obj']), fixture['str'])


    def test_bidirectional_conversion(self):

        for fixture in [ Fixtures.one, Fixtures.two, Fixtures.three, Fixtures.four ]:
            self.assertEqual(fixture['obj'], CSP.from_string(fixture['str']))


class TestSorting(unittest.TestCase):
    STANDARD_CSP_HEADERA = "default-src 'self'; script-src 'self' 'unsafe-eval' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://api-ssl.bitly.com; object-src 'self' https://www.youtube.com; report-uri https://twitter.com/scribes/csp_report"
    STANDARD_CSP_HEADERB = "default-src 'self'; object-src 'self' https://www.youtube.com; script-src 'self' 'unsafe-eval' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://api-ssl.bitly.com; report-uri https://twitter.com/scribes/csp_report"

    PRESTANDARD_CSP_HEADERA = "allow 'self'; options eval-script; script-src 'self' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://api-ssl.bitly.com; object-src 'self' https://www.youtube.com; report-uri /csp_report"
    PRESTANDARD_CSP_HEADERB = "allow 'self'; object-src 'self' https://www.youtube.com; options eval-script; script-src 'self' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://api-ssl.bitly.com; report-uri /csp_report"

    OLD_X_WEBKIT_CSPA = "script-src 'self' 'unsafe-eval' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://graph.facebook.com https://api-read.facebook.com https://api-ssl.bitly.com; object-src 'self' https://www.youtube.com; report-uri https://twitter.com/scribes/csp_report"
    OLD_X_WEBKIT_CSPB = "object-src 'self' https://www.youtube.com; script-src 'self' 'unsafe-eval' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://graph.facebook.com https://api-read.facebook.com https://api-ssl.bitly.com; report-uri https://twitter.com/scribes/csp_report"

    OLD_X_CONTENT_SECURITY_POLICYA = "options eval-script; script-src 'self' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://graph.facebook.com https://api-read.facebook.com https://api-ssl.bitly.com; object-src 'self' https://www.youtube.com; report-uri /csp_report"
    OLD_X_CONTENT_SECURITY_POLICYB = "object-src 'self' https://www.youtube.com; options eval-script; script-src 'self' https://*.twitter.com https://*.twimg.com https://ssl.google-analytics.com https://graph.facebook.com https://api-read.facebook.com https://api-ssl.bitly.com; report-uri /csp_report"

    def test_sorting(self):

        for p1, p2 in  [ (self.STANDARD_CSP_HEADERA, self.STANDARD_CSP_HEADERB),
                    (self.PRESTANDARD_CSP_HEADERA, self.PRESTANDARD_CSP_HEADERB),
                    (self.OLD_X_WEBKIT_CSPA, self.OLD_X_WEBKIT_CSPB),
                    (self.OLD_X_CONTENT_SECURITY_POLICYA, self.OLD_X_CONTENT_SECURITY_POLICYB) ]:

            self.assertEqual(str(CSP.from_string(p1)), str(CSP.from_string(p2)))



if __name__ == '__main__':
    unittest.main()

