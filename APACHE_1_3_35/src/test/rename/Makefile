
SRC=../..

all:
	@echo "run 'make rename' for renaming _THIS_ source tree"
	@echo "run 'make rename SRC=/path/to/apache-1.3/src' for other test trees"

rename: programs
	./rename.pl $(SRC)/buildmark.c \
	            $(SRC)/os \
				$(SRC)/main \
				$(SRC)/ap \
				$(SRC)/modules \
				$(SRC)/include

programs:
	@cd csubst; make
    
clean:
	@cd csubst; make clean

