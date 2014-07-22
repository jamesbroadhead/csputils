
from copy import copy
from pprint import pprint


class CSP(object):
    """ Object which represents Content-Security Policy rules

    Instantiate this with a dict representing your rules, then either str() or repr() it for a
    header string

    http://www.w3.org/TR/CSP/#syntax-and-algorithms
    """
    # Reserved Source Expressions. These must be quoted, or they will not function correctly.
    SELF = "'self'"
    UNSAFE_INLINE = "'unsafe-inline'"
    UNSAFE_EVAL = "'unsafe-eval'"
    NONE = "'none'"

    # the un-quoted form of strings which must be quoted in valid CSP
    reserved_source_expressions = [ i.strip("'")
                                    for i in SELF, UNSAFE_INLINE, UNSAFE_EVAL, NONE ]

    def __init__(self, content):
        """
        @param content: A dict of CSP keys to either strings or lists
        """
        self.content = self._parse_content(content)

    def __str__(self):
        return self.gen_policy(self.content)

    def __repr__(self):
        return '<%s:%s>' % (self.__class__.__name__, self.policy)

    def __eq__(self, other):
        return self.content == other.content

    def __neq__(self, other):
        return not self.__eq__(other)

    @classmethod
    def from_string(cls, str_):
        """ create a CSP object from a string-form CSP rule """
        key_values = [ key_values_str.strip().split(' ')
                       for key_values_str in str_.split(';') ]
        dct = { key_values[0]: key_values[1:] for key_values in key_values }
        return cls(dct)

    @classmethod
    def _parse_content(cls, content):
        """ normalise the input, so that all values are en-listed """
        return { k : cls._normalise_value(v) for k, v in content.items() }

    @classmethod
    def _normalise_value(cls, value_lst_or_str):
        if isinstance(value_lst_or_str, basestring):
            value = value_lst_or_str.split(' ')
        else:
            value = value_lst_or_str
        return value

    @staticmethod
    def _sorted_keys(content_):
        """ sort the keys, with report_uri last, if present """
        content = copy(content_)

        report_uri = content.pop('report-uri', None)
        keys = sorted(content.keys())
        if report_uri is not None:
            keys.append('report-uri')
        return keys

    @classmethod
    def _join_value(cls, value):
        """ Convert a value-list back into a space-separated string """
        if not isinstance(value, basestring):
            value = " ".join(value)
        return value

    @classmethod
    def _validate_value(cls, value):
        """
        The "special" source values of 'self', 'unsafe-inline', 'unsafe-eval', and 'none'
        must be quoted! "'self'". Without quotes they will not work as intended.
        http://django-csp.readthedocs.org/en/latest/configuration.html

        This is slightly stricter than the W3 spec, in that it disallows sources with the same
        name as any of the reserved_source_expressions (eg. if self or none resolved to a
        server). Conversely, it stops the user adding a non-functional, un-quoted source.

        Legal:   " 'self';", " 'self' "
        Illegal: " self;",   " self "
        """

        msg = ("You included a special value in your CSP, but did not wrap it in quotes."
               " eg. %s should be '%s'")
        for v in cls.reserved_source_expressions:
            if v in value:
                raise ValueError(msg % (v, v))
        return value

    @classmethod
    def gen_policy(cls, content):
        """
        @param content: dict of keys to a list of values
        """
        policy = [ '%s %s' % (k, cls._join_value(cls._validate_value(content.get(k))))
                   for k in cls._sorted_keys(content) ]

        return '; '.join(policy)
