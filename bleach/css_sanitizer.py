import re

import tinycss2


ALLOWED_CSS_PROPERTIES = frozenset(
    (
        "azimuth",
        "background-color",
        "border-bottom-color",
        "border-collapse",
        "border-color",
        "border-left-color",
        "border-right-color",
        "border-top-color",
        "clear",
        "color",
        "cursor",
        "direction",
        "display",
        "elevation",
        "float",
        "font",
        "font-family",
        "font-size",
        "font-style",
        "font-variant",
        "font-weight",
        "height",
        "letter-spacing",
        "line-height",
        "overflow",
        "pause",
        "pause-after",
        "pause-before",
        "pitch",
        "pitch-range",
        "richness",
        "speak",
        "speak-header",
        "speak-numeral",
        "speak-punctuation",
        "speech-rate",
        "stress",
        "text-align",
        "text-decoration",
        "text-indent",
        "unicode-bidi",
        "vertical-align",
        "voice-family",
        "volume",
        "white-space",
        "width",
    )
)


ALLOWED_SVG_PROPERTIES = frozenset(
    (
        "fill",
        "fill-opacity",
        "fill-rule",
        "stroke",
        "stroke-width",
        "stroke-linecap",
        "stroke-linejoin",
        "stroke-opacity",
    )
)


ALLOWED_URL_PROTOCOLS = frozenset(("http", "https", "data"))


URL_RE = re.compile(
    r"url\(\s*(?P<quote>['\"]?)(?P<url>.*?)(?P=quote)\s*\)",
    re.IGNORECASE | re.DOTALL,
)


def _compact_value(value):
    return re.sub(r"\s+", "", value).lower()


def _contains_parse_error(tokens):
    for token in tokens:
        if token.type == "error":
            return True
        if token.type == "function" and _contains_parse_error(token.arguments):
            return True
        if (
            token.type in ("{} block", "[] block", "() block")
            and _contains_parse_error(token.content)
        ):
            return True
    return False


class CSSSanitizer:
    """Sanitizes CSS in style attribute values.

    :arg allowed_css_properties: set of allowed CSS properties

    :arg allowed_svg_properties: set of allowed SVG properties

    :arg property_value_validators: dict mapping a property name to a
        validator callable for that property's value

        The validator receives the property value without ``!important`` and
        returns either the value to keep or ``None`` to reject the
        declaration. It may also raise ``ValueError`` to reject a value.

        Validated values also reject ``expression(...)``, ``javascript:`` and
        ``url()`` values using protocols outside ``allowed_url_protocols``.
        Properties without a validator continue to use property-name-only
        allowlisting.

    :arg allowed_url_protocols: protocols allowed in ``url()`` values for
        validated properties; defaults to http, https and data

    """

    def __init__(
        self,
        allowed_css_properties=ALLOWED_CSS_PROPERTIES,
        allowed_svg_properties=ALLOWED_SVG_PROPERTIES,
        property_value_validators=None,
        allowed_url_protocols=ALLOWED_URL_PROTOCOLS,
    ):
        self.allowed_css_properties = allowed_css_properties
        self.allowed_svg_properties = allowed_svg_properties
        if property_value_validators is not None:
            property_value_validators = {
                name.lower(): validator
                for name, validator in property_value_validators.items()
            }
        self.property_value_validators = property_value_validators
        self.allowed_url_protocols = frozenset(
            protocol.lower() for protocol in allowed_url_protocols
        )

    def _is_allowed_property(self, name):
        return (
            name in self.allowed_css_properties
            or name in self.allowed_svg_properties
        )

    def _is_safe_value(self, value):
        compact = _compact_value(value)
        if "expression(" in compact or "javascript:" in compact:
            return False

        for match in URL_RE.finditer(value):
            url = match.group("url").strip()
            protocol, separator, _remainder = url.partition(":")
            if separator and protocol.strip().lower() not in self.allowed_url_protocols:
                return False

        return True

    def _sanitize_declaration(self, token):
        if not self._is_allowed_property(token.lower_name):
            return None

        if self.property_value_validators is None:
            return token

        validator = self.property_value_validators.get(token.lower_name)
        if validator is None:
            return token

        if _contains_parse_error(token.value):
            return None

        value = tinycss2.serialize(token.value).strip()
        if not self._is_safe_value(value):
            return None

        try:
            normalized_value = validator(value)
        except ValueError:
            return None

        if normalized_value is None:
            return None

        if not isinstance(normalized_value, str):
            raise TypeError(
                "validator for property %r must return a str or None, not %r"
                % (token.lower_name, type(normalized_value))
            )

        if not self._is_safe_value(normalized_value):
            return None

        if normalized_value != value:
            token.value = tinycss2.parse_component_value_list(
                " " + normalized_value
            )

        return token

    def _sanitize_at_rule(self, token):
        if token.lower_at_keyword != "media" or token.content is None:
            return None

        inner_tokens = tinycss2.parse_declaration_list(
            tinycss2.serialize(token.content)
        )
        new_inner_tokens = []
        for inner_token in inner_tokens:
            if inner_token.type == "declaration":
                inner_token = self._sanitize_declaration(inner_token)
                if inner_token is not None:
                    new_inner_tokens.append(inner_token)
            elif inner_token.type in ("comment", "whitespace"):
                if new_inner_tokens and new_inner_tokens[-1].type != inner_token.type:
                    new_inner_tokens.append(inner_token)

        if not new_inner_tokens:
            return None

        token.content = tinycss2.parse_component_value_list(
            " " + tinycss2.serialize(new_inner_tokens)
        )
        return token

    def sanitize_css(self, style):
        """Sanitizes css in style tags"""
        parsed = tinycss2.parse_declaration_list(style)

        if not parsed:
            return ""

        new_tokens = []
        for token in parsed:
            if token.type == "declaration":
                token = self._sanitize_declaration(token)
                if token is not None:
                    new_tokens.append(token)
            elif token.type == "at-rule" and self.property_value_validators is not None:
                token = self._sanitize_at_rule(token)
                if token is not None:
                    new_tokens.append(token)
            elif token.type in ("comment", "whitespace"):
                if new_tokens and new_tokens[-1].type != token.type:
                    new_tokens.append(token)

            # NOTE(willkg): We currently don't handle ParseError tokens, so
            # they get silently thrown out. AtRule tokens are also thrown out
            # unless value validation is enabled, in which case @media rules
            # are sanitized and retained.

        if not new_tokens:
            return ""

        return tinycss2.serialize(new_tokens).strip()
