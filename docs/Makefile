# Build API docs with sphinx
# FIXME: set build dir from configure.

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = libwally-core
SOURCEDIR     = source
BUILDDIR      = build
MODULES = core crypto address bip32 bip38 bip39 script transaction
#FIXME = elements

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile
.PRECIOUS: $(MODULES:%=$(SOURCEDIR)/%.rst)

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile $(MODULES:%=$(SOURCEDIR)/%.rst)
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

$(SOURCEDIR)/%.rst: ../include/wally_%.h
	python ../tools/extract_docs.py $< >$@
