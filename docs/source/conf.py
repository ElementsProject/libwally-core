# -*- coding: utf-8 -*-
#
# libwally-core documentation build configuration file
SCANNING, DOCS, FUNC = 1, 2, 3

from os import getenv
# DUMP_FUNCS/DUMP_INTERNAL are used by tools/build_wrappers.py to auto-generate wrapper code
DUMP_FUNCS = getenv("WALLY_DOC_DUMP_FUNCS") is not None
DUMP_INTERNAL = DUMP_FUNCS and getenv("WALLY_DOC_DUMP_INTERNAL") is not None

def get_doc_lines(l):
    if l.startswith('.. '):
        return ['   ' + l, '']
    return ['   ' + l]

def preprocess_output_doc_line(l):
    text = l
    if 'FIXED_SIZED_OUTPUT(' in l:
        parts = [p.strip() for p in l[len('FIXED_SIZED_OUTPUT('):-1].split(',')]
        len_param, param, size = parts
        text = ':param {}: Size of ``{}``. Must be `{}`.'.format(len_param, param, size)
    elif 'MAX_SIZED_OUTPUT(' in l:
        parts = [p.strip() for p in l[len('FIXED_SIZED_OUTPUT('):-1].split(',')]
        len_param, param, max_size = parts
        text = ':param {}: Size of ``{}``. Passing `{}` will ensure the buffer is large enough.'.format(len_param, param, max_size)
    return '* ' + l if l else None, text

def output_func(docs, func):
    is_normal_ret = 'WALLY_CORE_API int' in func
    func = func[:-1].replace('WALLY_CORE_API','').strip()
    func = func.replace(',',', ').replace('  ', ' ')
    ret = ['.. c:function:: ' + func, '']
    is_variable_buffer_ret = 'unsigned char *bytes_out, size_t len, size_t *written' in func
    meta = []
    for l in docs:
        m, docs = preprocess_output_doc_line(l)
        ret.extend(get_doc_lines(docs))
        if m:
            meta.append(m)
    if ret[-1] != '':
        ret.append('')
    if is_normal_ret:
        if is_variable_buffer_ret:
            ret.append('   :return: See :ref:`variable-length-output-buffers`')
        else:
            ret.append('   :return: See :ref:`error-codes`')
    ret.append('')
    ret.append('')
    if DUMP_FUNCS:
        # Dump function definitions/metadata
        print('%s' % func)
        for m in meta:
            print('%s' % m)
    return ret

def preprocess_input_doc_line(l):
    return l # No-op for now

def extract_docs(infile, outfile):

    lines = [l.strip() for l in open(infile).readlines()]
    if DUMP_INTERNAL:
        title, constant_title = 'unused', 'unused'
    else:
        base_title = infile.split('wally_')[1][:-2].title().replace('_', '-')
        title, constant_title = base_title + ' Functions', base_title + ' Constants'
    title_markup, constant_markup = '=' * len(title), '-' * len(constant_title)
    output, current, func, state = [title, title_markup, ''], [], '', SCANNING
    constants, last_one_liner = [' ', constant_title, constant_markup, ''], ''

    for l in lines:
        # Allow one-liner internal functions with no doc comments
        if DUMP_INTERNAL and state == SCANNING and l.startswith('WALLY_CORE_API'):
            state = FUNC

        if state == SCANNING:
            if l.startswith('/***'):
                mark, details = l[4:-2].strip().split(' ', 1)
                constants.extend([f'.. _{mark}:', '', details, '^' *len(details)])
            elif l.startswith('/**'):
                if '*/' in l:
                    last_one_liner = l[3:-2].strip()
                else:
                    current, func, state = [l[3:]], '', DOCS
            elif l.startswith('#define ') and ' ' in l[len('#define '):]: # and '/*' not in l:
                c, remainder = l[len('#define '):].strip().split(' ', 1)
                if '/* ' in remainder:
                    remainder = remainder.split('/* ')[0].strip()
                if '/**' in remainder:
                    last_one_liner = remainder.split('/**')[1][:-2]
                constants.extend(['.. c:macro:: ' + c.strip(), ' ',
                                  '    ' + last_one_liner.strip(), ''])
                last_one_liner = ''
            else:
                last_one_liner = ''
        elif state == DOCS:
            if l == '*/':
                state = FUNC
            else:
                assert l.startswith('*'), l
                if l.startswith('*|'):
                    current[-1] += ' ' + l[2:].strip()
                else:
                    if l.startswith('* .. note::') and current[-1]:
                        current.append('') # A blank line ensures notes format correctly
                    l = preprocess_input_doc_line(l[1:].strip())
                    current.append(l)
        else: # FUNC
            func += l
            if ');' in func:
                output.extend(output_func(current, func))
                if DUMP_INTERNAL:
                    current, func = '', ''
                state = SCANNING

    if len(constants) > 4:
        output.extend(constants)
    with open(outfile, 'w') as f:
        f.write('\n'.join(output))

# Generate the documentation source files
if DUMP_INTERNAL:
    for m in ['bip32_int', 'transaction_int']:
        extract_docs('../../src/%s.h' % m, '%s.rst' % m)
    extract_docs('../../include/wally_psbt_members.h', 'psbt_members.rst')
else:
    for m in [
        'address', 'anti_exfil', 'bip32', 'bip38', 'bip39', 'bip85',
        'coinselection', 'core', 'crypto', 'descriptor', 'elements',
        'map', 'psbt', 'script', 'symmetric', 'transaction'
        ]:
        extract_docs('../../include/wally_%s.h' % m, '%s.rst' % m)

# -- General configuration ------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
#
# needs_sphinx = '1.0'

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = ['sphinx.ext.ifconfig',
    'sphinx.ext.githubpages']

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
#
# source_suffix = ['.rst', '.md']
source_suffix = '.rst'

default_role = 'any'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = u'libwally-core'
copyright = u'2022, Jon Griffiths'
author = u'Jon Griffiths'

# The version info for the project you're documenting, acts as replacement for
# |version| and |release|, also used in various other places throughout the
# built documents.
#
# The short X.Y version.
version = u'0.9.2'
# The full version, including alpha/beta/rc tags.
release = version

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
language = None

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This patterns also effect to html_static_path and html_extra_path
exclude_patterns = []

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = False


# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
#
# html_theme_options = {}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']


# -- Options for HTMLHelp output ------------------------------------------

# Output file base name for HTML help builder.
htmlhelp_basename = '%sdoc' % project


# -- Options for LaTeX output ---------------------------------------------

latex_elements = {
    # The paper size ('letterpaper' or 'a4paper').
    #
    # 'papersize': 'letterpaper',

    # The font size ('10pt', '11pt' or '12pt').
    #
    # 'pointsize': '10pt',

    # Additional stuff for the LaTeX preamble.
    #
    # 'preamble': '',

    # Latex figure (float) alignment
    #
    # 'figure_align': 'htbp',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
    (master_doc, '%s.tex' % project, u'%s Documentation' % project,
     author, 'manual'),
]


# -- Options for manual page output ---------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    (master_doc, project, u'%s Documentation' % project,
     [author], 1)
]


# -- Options for Texinfo output -------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
    (master_doc, project, u'%s Documentation' % project,
     author, project, 'The libwally Bitcoin library.',
     'Miscellaneous'),
]
