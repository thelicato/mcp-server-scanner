package com.mcpscanner.checks.catalog.templateinjection;

enum TemplateSyntax {
    DOUBLE_BRACES("{{", "}}", "Jinja2, Twig, Nunjucks or another double-brace engine"),
    DOLLAR_BRACES("${", "}",
            "FreeMarker, Mako, Thymeleaf or JSP expression language, or a JavaScript template literal"),
    ERB_TAG("<%= ", " %>", "ERB or EJS"),
    HASH_BRACES("#{", "}", "Ruby string interpolation, Pug or Slim"),
    SINGLE_BRACES("{", "}", "Smarty or another single-brace engine");

    private final String open;
    private final String close;
    private final String engines;

    TemplateSyntax(String open, String close, String engines) {
        this.open = open;
        this.close = close;
        this.engines = engines;
    }

    String wrap(String expression) {
        return open + expression + close;
    }

    String engines() {
        return engines;
    }
}
