

help:
	@echo "  make lib            : produce ucrypt.js"
	@echo "  make doc            : produce doc"
	@echo "  make dist           : aka 'make lib doc'"
	@echo "  make clean          : clean dist'"
	@echo

doc:
	rm -rf dist/doc
	mkdir -p dist/doc
	/opt/jsdoc/jsdoc -c doc-conf.json

lib:
	rm -rf dist/lib
	mkdir -p  dist/lib
	cp -r ext/jsbn  dist/lib
	cp -r src/*js   dist/lib

dist: doc lib


clean:
	rm -rf dist
